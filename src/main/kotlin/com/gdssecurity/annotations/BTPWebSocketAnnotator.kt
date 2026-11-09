/*
 * Copyright 2023 Aon plc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gdssecurity.annotations

import burp.api.montoya.core.Annotations
import burp.api.montoya.core.Registration
import burp.api.montoya.logging.Logging
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction
import burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage
import burp.api.montoya.proxy.websocket.InterceptedTextMessage
import burp.api.montoya.proxy.websocket.ProxyMessageHandler
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler
import burp.api.montoya.proxy.websocket.TextMessageReceivedAction
import burp.api.montoya.proxy.websocket.TextMessageToBeSentAction
import burp.api.montoya.websocket.Direction
import com.gdssecurity.settings.BTPSettings
import java.util.concurrent.atomic.AtomicInteger

/**
 * Writes notes on Proxy WebSocket messages of Blazor endpoints. Every callback forwards the message unchanged, and
 * notes are written in the to-be-sent callbacks so they describe what the peer receives after interception edits.
 */
class BTPWebSocketAnnotator(
    private val proxy: Proxy,
    private val settings: BTPSettings,
    private val logging: Logging,
) : ProxyWebSocketCreationHandler {
    private val lock = Any()
    private var registration: Registration? = null
    private val sessions = mutableSetOf<Session>()
    private val errors = AtomicInteger()

    /** Registers or deregisters the Proxy hook to match [options]; turning annotations off releases every socket. */
    fun update(options: BTPSettings.Options) {
        synchronized(lock) {
            if (!options.annotateMessages) stop()
            else if (registration == null) registration = proxy.registerWebSocketCreationHandler(this)
        }
    }

    fun close() {
        synchronized(lock) { stop() }
    }

    private fun stop() {
        registration?.deregister()
        registration = null
        val stopped = sessions.toList()
        sessions.clear()
        stopped.forEach(Session::stop)
    }

    override fun handleWebSocketCreation(creation: ProxyWebSocketCreation) {
        try {
            val options = settings.current
            if (!options.annotateMessages || !options.matchesPath(creation.upgradeRequest()?.pathWithoutQuery())) return
            val session = Session()
            synchronized(lock) {
                if (registration == null) return
                sessions += session
            }
            session.attach(creation.proxyWebSocket().registerProxyMessageHandler(session))
        } catch (failure: Exception) {
            report(failure)
        }
    }

    private fun report(failure: Throwable) {
        val count = errors.incrementAndGet()
        if (count > MAX_LOGGED_ERRORS) return
        val suffix = if (count == MAX_LOGGED_ERRORS) " Further annotation errors are not logged." else ""
        logging.logToError("[-] BTP stopped annotating a WebSocket: $failure.$suffix")
    }

    /** One socket. Burp may call from several threads, so state changes happen under the session's monitor. */
    private inner class Session : ProxyMessageHandler {
        private var conversation: CircuitConversation? = CircuitConversation()
        private var registration: Registration? = null

        override fun handleTextMessageReceived(message: InterceptedTextMessage): TextMessageReceivedAction =
            TextMessageReceivedAction.continueWith(message)

        override fun handleBinaryMessageReceived(message: InterceptedBinaryMessage): BinaryMessageReceivedAction =
            BinaryMessageReceivedAction.continueWith(message)

        override fun handleTextMessageToBeSent(message: InterceptedTextMessage): TextMessageToBeSentAction {
            annotate(message.direction(), message.annotations()) { message.payload().toByteArray(Charsets.UTF_8) }
            return TextMessageToBeSentAction.continueWith(message)
        }

        override fun handleBinaryMessageToBeSent(message: InterceptedBinaryMessage): BinaryMessageToBeSentAction {
            annotate(message.direction(), message.annotations()) { message.payload().bytes }
            return BinaryMessageToBeSentAction.continueWith(message)
        }

        override fun onClose() {
            synchronized(this) { conversation = null }
            synchronized(lock) { sessions -= this }
        }

        fun attach(handle: Registration) {
            val stopped = synchronized(this) {
                registration = handle
                conversation == null
            }
            if (stopped) handle.deregister()
        }

        fun stop() {
            val handle = synchronized(this) {
                conversation = null
                registration.also { registration = null }
            }
            handle?.deregister()
        }

        private fun annotate(direction: Direction, annotations: Annotations, payload: () -> ByteArray) {
            try {
                val note = synchronized(this) {
                    val flow = if (direction == Direction.CLIENT_TO_SERVER) Flow.CLIENT_TO_SERVER else Flow.SERVER_TO_CLIENT
                    conversation?.annotate(flow, payload())
                } ?: return
                if (!annotations.hasNotes()) annotations.setNotes(note)
            } catch (failure: Exception) {
                fail(failure)
            } catch (failure: StackOverflowError) {
                fail(failure)
            }
        }

        private fun fail(failure: Throwable) {
            synchronized(this) { conversation = null }
            report(failure)
        }
    }

    private companion object {
        const val MAX_LOGGED_ERRORS = 5
    }
}
