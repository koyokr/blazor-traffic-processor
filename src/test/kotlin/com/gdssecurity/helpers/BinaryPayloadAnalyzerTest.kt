package com.gdssecurity.helpers

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class BinaryPayloadAnalyzerTest {
    @Test
    fun exposesPrintableUtf8WithoutChangingTheBytes() {
        val bytes = """{"authenticated":true}""".toByteArray()

        val analysis = BinaryPayloadAnalyzer.analyze(bytes, "JS.ReceiveByteArray")

        assertEquals(bytes.size, analysis.getInt("Length"))
        assertEquals("Binary", analysis.getString("Format"))
        assertEquals("""{"authenticated":true}""", analysis.getString("Utf8Text"))
        assertFalse(analysis.has("RenderBatch"))
    }

    @Test
    fun extractsRenderBatchFramesAndStringTable() {
        val analysis = BinaryPayloadAnalyzer.analyze(renderBatchWithTextFrame("authenticated dashboard"), "JS.RenderBatch")
        val renderBatch = analysis.getJSONObject("RenderBatch")
        val frame = renderBatch.getJSONArray("ReferenceFrames").getJSONObject(0)

        assertEquals("BlazorRenderBatch", analysis.getString("Format"))
        assertEquals(1, renderBatch.getInt("StringTableCount"))
        assertEquals("authenticated dashboard", renderBatch.getJSONArray("Strings").getString(0))
        assertEquals("Text", frame.getString("Type"))
        assertEquals("authenticated dashboard", frame.getString("TextContent"))
    }

    @Test
    fun reportsMalformedRenderBatchWithoutThrowing() {
        val analysis = BinaryPayloadAnalyzer.analyze(ByteArray(40), "JS.RenderBatch")

        assertEquals("BlazorRenderBatch", analysis.getString("Format"))
        assertTrue(analysis.has("RenderBatchDecodeError"))
        assertFalse(analysis.has("RenderBatch"))
    }

    private fun renderBatchWithTextFrame(text: String): ByteArray {
        val textBytes = text.toByteArray()
        val batch = ByteArrayOutputStream()
        fun int32(value: Int) = batch.writeBytes(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array())

        val updatedComponentsOffset = batch.size()
        int32(0)
        val referenceFramesOffset = batch.size()
        listOf(1, 2, 0, 0, 0, 0).forEach(::int32)
        val disposedComponentIdsOffset = batch.size()
        int32(0)
        val disposedEventHandlerIdsOffset = batch.size()
        int32(0)
        val stringOffset = batch.size()
        batch.writeBytes(VarIntHelper.encodeVarInt(textBytes.size))
        batch.writeBytes(textBytes)
        val stringTableOffset = batch.size()
        int32(stringOffset)

        listOf(updatedComponentsOffset, referenceFramesOffset, disposedComponentIdsOffset,
            disposedEventHandlerIdsOffset, stringTableOffset).forEach(::int32)
        return batch.toByteArray()
    }
}
