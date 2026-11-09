package com.gdssecurity.annotations

import com.gdssecurity.helpers.ComponentDiff
import com.gdssecurity.helpers.EventHandlerId
import com.gdssecurity.helpers.RenderBatchWriter
import com.gdssecurity.helpers.RenderEdit
import com.gdssecurity.helpers.RenderFrame
import com.gdssecurity.helpers.VarIntHelper
import com.gdssecurity.messages.HubCodec
import com.gdssecurity.messages.HubMessage
import org.msgpack.core.MessagePack
import org.msgpack.value.ImmutableValue
import org.msgpack.value.Value
import org.msgpack.value.ValueFactory

/** Synthetic BlazorPack traffic for annotation tests. */
object BlazorWire {
    private val noHeaders = ValueFactory.newMap(emptyMap<Value, Value>())

    fun frame(message: HubMessage): ByteArray {
        val body = MessagePack.newDefaultBufferPacker().use { it.packValue(HubCodec.toWire(message)); it.toByteArray() }
        return VarIntHelper.encodeVarInt(body.size) + body
    }

    fun invocation(target: String, vararg args: Any?, id: String? = null): HubMessage =
        HubMessage.Invocation(noHeaders, id, target, ValueFactory.newArray(args.map(::value)), null)

    fun completion(id: String, value: Any?): HubMessage =
        HubMessage.Completion(noHeaders, id, com.gdssecurity.messages.CompletionResult.Value(value(value)))

    fun send(vararg messages: HubMessage): ByteArray = messages.map(::frame).reduce(ByteArray::plus)

    fun renderBatch(batchId: Long, vararg diffs: ComponentDiff, frames: List<RenderFrame>,
                    disposedComponents: List<Int> = emptyList(), disposedHandlers: List<Long> = emptyList()): HubMessage =
        invocation("JS.RenderBatch", batchId, RenderBatchWriter.batch(*diffs, frames = frames,
            disposedComponentIds = disposedComponents, disposedEventHandlerIds = disposedHandlers))

    fun dispatchEvent(callId: String, handler: Long, eventName: String, eventArgs: String,
                      fieldInfo: String = "null"): HubMessage = invocation("BeginInvokeDotNetFromJS", callId, null,
        "DispatchEventAsync", 1, """[{"eventHandlerId":$handler,"eventName":"$eventName","eventFieldInfo":$fieldInfo},$eventArgs]""")

    fun element(name: String, subtreeLength: Int) = RenderFrame.Element(subtreeLength, name)
    fun attribute(name: String, value: String?) = RenderFrame.Attribute(name, value, null)
    fun handler(name: String, id: Long) = RenderFrame.Attribute(name, null, EventHandlerId(id.toULong()))
    fun text(value: String) = RenderFrame.Text(value)
    fun diff(componentId: Int, vararg edits: RenderEdit) = ComponentDiff(componentId, edits.toList())
    fun id(value: Long) = EventHandlerId(value.toULong())

    private fun value(value: Any?): ImmutableValue = when (value) {
        null -> ValueFactory.newNil()
        is String -> ValueFactory.newString(value)
        is Int -> ValueFactory.newInteger(value)
        is Long -> ValueFactory.newInteger(value)
        is Boolean -> ValueFactory.newBoolean(value)
        is ByteArray -> ValueFactory.newBinary(value)
        else -> error("Unsupported test value $value")
    }
}
