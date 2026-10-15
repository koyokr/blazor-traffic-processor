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

package com.gdssecurity.editors

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.message.ContentType
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.requests.MalformedRequestException
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.ui.editor.extension.EditorMode
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.util.HexFormat
import java.util.Optional

/** Montoya test doubles; exercises request/response preservation without sending traffic. */
class BTPHttpEditorsTest {
    private val wire = HexFormat.of().parseHex("0b950180c0a44563686f9107")
    private val requestHeaders = "POST /_blazor?id=synthetic HTTP/1.1\r\nHost: example.test\r\nX-Note: 한글\r\n\r\n"
    private var previousFactory: MontoyaObjectFactory? = null
    private var contents = bytes(byteArrayOf())
    private var modified = false
    private var editable = false
    private var rewrites = 0
    private var inScope = true
    private var scopeLookups = 0
    private var bodyReads = 0
    private val errors = mutableListOf<String>()
    private val api = apiStub(MontoyaApi::class.java)

    @BeforeEach
    fun installFactory() {
        previousFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = stub(MontoyaObjectFactory::class.java) { method, args ->
            check(method.name == "byteArray")
            bytes(when (val value = args[0]) {
                is String -> value.toByteArray()
                is ByteArray -> value
                else -> error("Unexpected byteArray overload")
            })
        }
    }

    @AfterEach
    fun restoreFactory() {
        ObjectFactoryLocator.FACTORY = previousFactory
    }

    @Test
    fun malformedUrlsDisableBothEditorsWithoutLoggingOrBreakingLaterRequests() {
        val malformed = request(wire) { throw MalformedRequestException("URL is invalid.") }
        val requestEditor = BTPHttpRequestEditor(api, EditorMode.DEFAULT)
        val responseEditor = BTPHttpResponseEditor(api, EditorMode.DEFAULT)
        repeat(2) {
            assertFalse(requestEditor.isEnabledFor(pair(malformed)))
            assertFalse(responseEditor.isEnabledFor(pair(malformed, response(wire))))
        }
        assertFalse(requestEditor.isEnabledFor(null))
        assertFalse(responseEditor.isEnabledFor(null))
        assertTrue(requestEditor.isEnabledFor(pair(request(wire))))
        assertTrue(responseEditor.isEnabledFor(pair(request(wire), response(wire))))
        assertTrue(errors.isEmpty())
        assertEquals(0, rewrites)
    }

    @Test
    fun missingMessagesDisableEditorsWithoutScopeOrBodyAccess() {
        val requestEditor = BTPHttpRequestEditor(api, EditorMode.DEFAULT)
        val responseEditor = BTPHttpResponseEditor(api, EditorMode.DEFAULT)
        assertFalse(requestEditor.isEnabledFor(pair(null)))
        assertFalse(responseEditor.isEnabledFor(pair(null, response(wire))))
        assertFalse(responseEditor.isEnabledFor(pair(request(wire))))
        assertEquals(0, scopeLookups)
        assertEquals(0, bodyReads)
    }

    @Test
    fun ordinaryUrlsSkipScopeAndBodyAccessForBothEditors() {
        val ordinary = pair(request(wire) { "https://example.test/health" }, response(wire))
        assertFalse(BTPHttpRequestEditor(api, EditorMode.DEFAULT).isEnabledFor(ordinary))
        assertFalse(BTPHttpResponseEditor(api, EditorMode.DEFAULT).isEnabledFor(ordinary))
        assertEquals(0, scopeLookups)
        assertEquals(0, bodyReads)
    }

    @Test
    fun jsonRequestsSkipScopeAndBodyAccess() {
        val json = pair(request(wire, contentType = ContentType.JSON))
        assertFalse(BTPHttpRequestEditor(api, EditorMode.DEFAULT).isEnabledFor(json))
        assertEquals(0, scopeLookups)
        assertEquals(0, bodyReads)
    }

    @Test
    fun outOfScopeMessagesSkipBodiesAndRecoverWhenScopeChanges() {
        val message = pair(request(wire), response(wire))
        val requestEditor = BTPHttpRequestEditor(api, EditorMode.DEFAULT)
        val responseEditor = BTPHttpResponseEditor(api, EditorMode.DEFAULT)
        inScope = false
        assertFalse(requestEditor.isEnabledFor(message))
        assertFalse(responseEditor.isEnabledFor(message))
        assertEquals(2, scopeLookups)
        assertEquals(0, bodyReads)
        inScope = true
        assertTrue(requestEditor.isEnabledFor(message))
        assertTrue(responseEditor.isEnabledFor(message))
        assertEquals(4, scopeLookups)
        assertEquals(2, bodyReads)
        assertTrue(errors.isEmpty())
    }

    @Test
    fun unchangedRequestIsReturnedByIdentityWithoutSerialization() {
        val original = request(wire)
        val editor = BTPHttpRequestEditor(api, EditorMode.DEFAULT)
        assertNull(editor.request)
        editor.setRequestResponse(pair(original))
        val count = rewrites
        assertSame(original, editor.request)
        assertEquals(count, rewrites)
        assertTrue(editable)
        assertFalse(editor.isModified)
        assertNull(editor.selectedData())
        assertTrue(editor.isEnabledFor(pair(original)))
    }

    @Test
    fun editsOnlyTheBodyAndHandlesUnicodeHeaderOffsets() {
        val original = request(wire)
        val editor = BTPHttpRequestEditor(api, EditorMode.DEFAULT)
        editor.setRequestResponse(pair(original))
        edit(requestHeaders + "[{MessageType:1,Headers:0,Target:Echo,Arguments:[8]}]")
        val changed = requireNotNull(editor.request)
        assertArrayEquals(HexFormat.of().parseHex("0b950180c0a44563686f9108"), changed.body().bytes)
        assertTrue(changed.toByteArray().toString().startsWith(requestHeaders))
        assertArrayEquals(wire, original.body().bytes)
        assertTrue(errors.isEmpty())
    }

    @Test
    fun invalidEditsKeepTheOriginalRequest() {
        val original = request(wire)
        val editor = BTPHttpRequestEditor(api, EditorMode.DEFAULT)
        editor.setRequestResponse(pair(original))
        for (text in listOf(requestHeaders + "not json", requestHeaders + "[{MessageType:1}]",
                requestHeaders, "[{MessageType:6}]")) {
            edit(text)
            assertSame(original, editor.request)
        }
        assertEquals(4, errors.size)
    }

    @Test
    fun readOnlyRequestsCannotBeRewrittenEvenIfRawEditorReportsModification() {
        val original = request(wire)
        val editor = BTPHttpRequestEditor(api, EditorMode.READ_ONLY)
        editor.setRequestResponse(pair(original))
        assertFalse(editable)
        edit(requestHeaders + "[{MessageType:6}]")
        assertFalse(editor.isModified)
        assertSame(original, editor.request)
    }

    @Test
    fun failedDecodeClearsThePreviousPreviewAndPreservesTheNewOriginal() {
        val editor = BTPHttpRequestEditor(api, EditorMode.DEFAULT)
        editor.setRequestResponse(pair(request(wire)))
        val malformed = request(byteArrayOf(0x80.toByte()))
        editor.setRequestResponse(pair(malformed))
        assertEquals("Unable to decode BlazorPack payload.", contents.toString())
        assertFalse(editable)
        edit(requestHeaders + "[{MessageType:6}]")
        assertSame(malformed, editor.request)
        assertFalse(editor.isModified)
        assertFalse(editor.isEnabledFor(pair(malformed)))
        editor.setRequestResponse(null)
        assertNull(editor.request)
        assertEquals(0, contents.length())
    }

    @Test
    fun responsePreviewAlwaysReturnsTheOriginalAndResetsAfterFailure() {
        val original = response(wire)
        val editor = BTPHttpResponseEditor(api, EditorMode.DEFAULT)
        assertNull(editor.response)
        editor.setRequestResponse(pair(request(wire), original))
        assertTrue(contents.toString().contains("Echo"))
        assertFalse(editable)
        edit("[{MessageType:6}]")
        assertSame(original, editor.response)
        assertFalse(editor.isModified)
        val malformed = response(byteArrayOf(0x80.toByte()))
        editor.setRequestResponse(pair(request(wire), malformed))
        assertSame(malformed, editor.response)
        assertEquals("Unable to decode BlazorPack payload.", contents.toString())
        editor.setRequestResponse(null)
        assertNull(editor.response)
        assertNull(editor.selectedData())
        assertEquals(0, contents.length())
    }

    private fun edit(text: String) {
        contents = bytes(text.toByteArray())
        modified = true
    }

    private fun <T> apiStub(type: Class<T>): T = stub(type) { method, args ->
        when (method.name) {
            "getContents" -> contents
            "setContents" -> { contents = args[0] as BurpByteArray; modified = false; null }
            "setEditable" -> { editable = args[0] as Boolean; null }
            "isModified" -> modified
            "selection" -> Optional.empty<Any>()
            "scope" -> { scopeLookups++; apiStub(method.returnType) }
            "isInScope" -> inScope
            "logToError" -> { errors.add(args[0] as String); null }
            else -> {
                check(method.returnType.isInterface) { "Unexpected API call: $method" }
                apiStub(method.returnType)
            }
        }
    }

    private fun request(
        body: ByteArray,
        contentType: ContentType = ContentType.entries.first { it != ContentType.JSON },
        url: () -> String = { "https://example.test/_blazor?id=synthetic" },
    ): HttpRequest = stub(HttpRequest::class.java) { method, args ->
        when (method.name) {
            "body" -> { bodyReads++; bytes(body) }
            "toByteArray" -> bytes(requestHeaders.toByteArray() + body)
            "withBody" -> { rewrites++; request((args[0] as BurpByteArray).bytes) }
            "url" -> url()
            "httpVersion" -> "HTTP/1.1"
            "contentType" -> contentType
            else -> error("Unexpected request call: $method")
        }
    }

    private fun response(body: ByteArray): HttpResponse = stub(HttpResponse::class.java) { method, args ->
        when (method.name) {
            "body" -> { bodyReads++; bytes(body) }
            "toByteArray" -> bytes("HTTP/1.1 200 OK\r\n\r\n".toByteArray() + body)
            "withBody" -> response((args[0] as BurpByteArray).bytes)
            "httpVersion" -> "HTTP/1.1"
            else -> error("Unexpected response call: $method")
        }
    }

    private fun pair(request: HttpRequest?, response: HttpResponse? = null): HttpRequestResponse =
        stub(HttpRequestResponse::class.java) { method, _ ->
            when (method.name) {
                "request" -> request
                "response" -> response
                else -> error("Unexpected request/response call: $method")
            }
        }

    private fun bytes(value: ByteArray): BurpByteArray = stub(BurpByteArray::class.java) { method, _ ->
        when (method.name) {
            "getBytes" -> value.copyOf()
            "length" -> value.size
            "toString" -> value.toString(Charsets.UTF_8)
            else -> error("Unexpected byte array call: $method")
        }
    }

    private fun <T> stub(type: Class<T>, handler: (Method, Array<out Any?>) -> Any?): T =
        type.cast(Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            handler(method, args ?: emptyArray())
        })
}
