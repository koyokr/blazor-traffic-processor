package com.gdssecurity.helpers

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.msgpack.core.MessagePack

class BlazorFrameValidatorTest {
    @Test
    fun acceptsOneOrMoreLengthPrefixedHubMessages() {
        val invocation = invocation("DispatchEventAsync")

        assertTrue(BlazorFrameValidator.isBlazorPack(invocation))
        assertTrue(BlazorFrameValidator.isBlazorPack(invocation + invocation("EndInvokeJSFromDotNet")))
    }

    @Test
    fun rejectsSignalRHandshakeAndTruncatedMessages() {
        assertFalse(BlazorFrameValidator.isBlazorPack(("""{"protocol":"blazorpack","version":1}""" + "\u001e").toByteArray()))

        val invocation = invocation("DispatchEventAsync")
        assertFalse(BlazorFrameValidator.isBlazorPack(invocation.copyOf(invocation.size - 1)))
    }

    @Test
    fun reassemblesAHubMessageSplitAcrossWebSocketHistoryRows() {
        val framed = invocation("JS.RenderBatch".repeat(400))
        val first = framed.copyOfRange(0, 4096)
        val second = framed.copyOfRange(4096, framed.size)
        val chunks = listOf(first, second)

        assertFalse(BlazorFrameValidator.isBlazorPack(first))
        assertFalse(BlazorFrameValidator.isBlazorPack(second))
        assertArrayEquals(framed, BlazorFrameValidator.reassembleContaining(chunks, 0, 8, 1_000_000))
        assertArrayEquals(framed, BlazorFrameValidator.reassembleContaining(chunks, 1, 8, 1_000_000))
    }

    @Test
    fun doesNotJoinUnrelatedOrOversizedChunks() {
        assertNull(BlazorFrameValidator.reassembleContaining(listOf(invocation("First"), invocation("Second")), 0, 8, 1_000_000))
        assertNull(BlazorFrameValidator.reassembleContaining(listOf(invocation("Large").copyOf(3), ByteArray(100)), 0, 8, 32))
    }

    private fun invocation(target: String): ByteArray {
        val message = MessagePack.newDefaultBufferPacker().use {
            it.packArrayHeader(5).packInt(1).packMapHeader(0).packNil().packString(target).packArrayHeader(0)
            it.toByteArray()
        }
        return VarIntHelper.encodeVarInt(message.size) + message
    }
}
