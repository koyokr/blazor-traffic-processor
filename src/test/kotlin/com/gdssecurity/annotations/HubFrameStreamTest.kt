package com.gdssecurity.annotations

import com.gdssecurity.annotations.BlazorWire.frame
import com.gdssecurity.annotations.BlazorWire.invocation
import com.gdssecurity.messages.HubMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class HubFrameStreamTest {
    private val handshake = "{}\u001e".toByteArray()
    private val messages = listOf(
        HubMessage.Ping,
        invocation("JS.BeginInvokeJS", 6, "eval", """["1"]""", 0, 0),
        invocation("JS.ReceiveByteArray", 1, ByteArray(300) { it.toByte() }),
    )
    private val wire = handshake + messages.map(::frame).reduce(ByteArray::plus)
    private val expected = listOf(HubFrameStream.Event.Handshake("{}")) + messages.map(HubFrameStream.Event::Message)

    private fun HubFrameStream.collect(chunk: ByteArray, events: MutableList<HubFrameStream.Event>) =
        accept(chunk) { events += it }

    @Test
    fun emitsTheHandshakeAndEveryFrameOfOneWebSocketMessage() {
        val events = mutableListOf<HubFrameStream.Event>()

        val pending = HubFrameStream().collect(wire, events)

        assertEquals(expected, events)
        assertNull(pending)
    }

    @Test
    fun reassemblesFramesSplitAtEveryByteBoundary() {
        for (split in 1 until wire.size) {
            val events = mutableListOf<HubFrameStream.Event>()
            val stream = HubFrameStream()
            stream.collect(wire.copyOfRange(0, split), events)
            val pending = stream.collect(wire.copyOfRange(split, wire.size), events)
            assertEquals(expected, events, "split at $split")
            assertNull(pending, "split at $split")
        }
    }

    @Test
    fun reassemblesFramesDeliveredOneByteAtATime() {
        val events = mutableListOf<HubFrameStream.Event>()
        val stream = HubFrameStream()

        val pending = wire.map { stream.collect(byteArrayOf(it), events) }

        assertEquals(expected, events)
        assertNull(pending.last())
    }

    @Test
    fun reportsHowMuchOfAPartialFrameHasArrived() {
        val last = frame(messages.last())
        val stream = HubFrameStream()
        stream.accept(handshake) {}

        assertEquals(HubFrameStream.Pending(1, null), stream.accept(last.copyOfRange(0, 1)) {})
        assertEquals(HubFrameStream.Pending(98, last.size - 2), stream.accept(last.copyOfRange(1, 100)) {})
    }

    @Test
    fun dropsTheRestOfAMessageAfterLostFramingAndResumesAtTheNextMessage() {
        val events = mutableListOf<HubFrameStream.Event>()
        val stream = HubFrameStream()
        stream.collect(handshake, events)

        val pending = stream.collect(byteArrayOf(0) + frame(HubMessage.Ping), events)
        stream.collect(frame(HubMessage.Ping), events)

        assertNull(pending)
        assertEquals(listOf(HubFrameStream.Event.Handshake("{}"), HubFrameStream.Event.Malformed("invalid frame length 0"),
            HubFrameStream.Event.Message(HubMessage.Ping)), events)
    }

    @Test
    fun treatsAStreamThatDoesNotStartWithJsonAsFramesOnly() {
        val events = mutableListOf<HubFrameStream.Event>()

        HubFrameStream().collect(frame(HubMessage.Ping), events)

        assertEquals(listOf(HubFrameStream.Event.Message(HubMessage.Ping)), events)
    }
}
