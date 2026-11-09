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

import com.gdssecurity.helpers.EventHandlerId
import com.gdssecurity.helpers.RenderBatch
import com.gdssecurity.helpers.RenderEdit
import com.gdssecurity.helpers.RenderFrame

/** A listener element as of the last render BTP applied; [disabled] is that render's state, not the browser's. */
data class ElementLabel(
    val tag: String?,
    val id: String?,
    val name: String?,
    val type: String?,
    val placeholder: String?,
    val text: String?,
    val disabled: Boolean,
)

/**
 * What a batch asked the browser to change, in edit order. Insertions report elements a user can act on or that run
 * code, plus text and markup outside them. Targets are null for components BTP has not mirrored since creation.
 */
sealed interface RenderChange {
    data class Inserted(val element: ElementLabel) : RenderChange
    data class TextShown(val text: String) : RenderChange
    data class MarkupShown(val markup: String) : RenderChange
    data class AttributeSet(val target: ElementLabel?, val name: String, val value: String) : RenderChange
    data class AttributeRemoved(val target: ElementLabel?, val name: String) : RenderChange
    data object Removed : RenderChange
    data class Unsynchronized(val componentId: Int) : RenderChange
    data object Overflow : RenderChange
}

sealed interface BatchOutcome {
    data class Applied(val changes: List<RenderChange>) : BatchOutcome
    data object Retransmitted : BatchOutcome
}

/**
 * Per-socket mirror of the logical children that blazor.web.js BrowserRenderer keeps per component, so event handler
 * IDs resolve to the element they are bound to. A component is mirrored only from a creation BTP witnessed (root
 * attach or a placeholder inserted by a mirrored parent); any edit the browser would reject drops it, because a guessed
 * tree would attribute events to the wrong element.
 */
class RenderTreeMirror(private val maxNodes: Int = 50_000) {
    private sealed interface Node
    private class Element(val tag: String?) : Node {
        val attributes = LinkedHashMap<String, String>()
        val handlers = HashMap<String, EventHandlerId>()
        val children = mutableListOf<Node>()
    }
    private class Text(var text: String?) : Node
    private class Markup(val markup: String?) : Node
    private class ComponentSlot(val componentId: Int) : Node

    private class Binding(val element: Element, val eventName: String)
    private class Desync : RuntimeException(null, null, false, false)

    private val mirrored = HashMap<Int, MutableList<Node>>()
    private val bindings = HashMap<EventHandlerId, Binding>()
    private var lastBatchId: Long? = null
    private var nodes = 0

    fun attachRoot(componentId: Int) {
        release(componentId)
        mirrored[componentId] = mutableListOf()
    }

    /** Edits first, then disposed components, then disposed handlers: the order of blazor.web.js renderBatch. */
    fun apply(batchId: Long, batch: RenderBatch): BatchOutcome {
        val last = lastBatchId
        if (last != null && batchId <= last) return BatchOutcome.Retransmitted
        if (last != null && batchId != last + 1) invalidate()
        lastBatchId = batchId
        val changes = mutableListOf<RenderChange>()
        for (diff in batch.updatedComponents) Diff(diff.componentId, batch.referenceFrames, changes).run(diff.edits)
        batch.disposedComponentIds.forEach(::release)
        for (id in batch.disposedEventHandlerIds) {
            val binding = bindings.remove(id) ?: continue
            binding.element.handlers.remove(binding.eventName, id)
        }
        if (nodes > maxNodes || bindings.size > maxNodes || mirrored.size > maxNodes) {
            invalidate()
            changes += RenderChange.Overflow
        }
        return BatchOutcome.Applied(changes)
    }

    fun element(handlerId: EventHandlerId): ElementLabel? = bindings[handlerId]?.let { label(it.element) }

    /** Drops every mirrored tree; only components created after this point are mirrored again. */
    fun invalidate() {
        mirrored.clear()
        bindings.clear()
        nodes = 0
    }

    private fun release(componentId: Int) {
        val children = mirrored.remove(componentId) ?: return
        children.forEach(::detach)
    }

    private fun detach(node: Node) {
        nodes--
        if (node !is Element) return
        for ((eventName, id) in node.handlers) {
            if (bindings[id]?.let { it.element === node && it.eventName == eventName } == true) bindings.remove(id)
        }
        node.children.forEach(::detach)
    }

    private inner class Diff(
        private val componentId: Int,
        private val frames: List<RenderFrame>,
        private val changes: MutableList<RenderChange>,
    ) {
        private var parent: MutableList<Node>? = mirrored[componentId]
        private val ancestors = ArrayDeque<MutableList<Node>>()
        private var permutation: MutableList<Pair<Int, Int>>? = null

        fun run(edits: List<RenderEdit>) {
            if (parent == null) {
                changes += RenderChange.Unsynchronized(componentId)
                edits.forEach(::describe)
                return
            }
            try {
                edits.forEach { apply(it, parent!!) }
            } catch (_: Desync) {
                release(componentId)
                nodes = mirrored.values.sumOf { children -> children.sumOf(::size) }
                changes += RenderChange.Unsynchronized(componentId)
            }
        }

        private fun apply(edit: RenderEdit, siblings: MutableList<Node>) {
            when (edit) {
                is RenderEdit.PrependFrame -> {
                    ensure(edit.siblingIndex in 0..siblings.size)
                    val built = build(edit.frameIndex)
                    siblings.addAll(edit.siblingIndex, built)
                    built.forEach(::attach)
                    report(built)
                }
                is RenderEdit.RemoveFrame -> {
                    ensure(edit.siblingIndex in siblings.indices)
                    detach(siblings.removeAt(edit.siblingIndex))
                    changes += RenderChange.Removed
                }
                is RenderEdit.SetAttribute -> {
                    val element = siblings.getOrNull(edit.siblingIndex) as? Element ?: throw Desync()
                    val attribute = frames.getOrNull(edit.frameIndex) as? RenderFrame.Attribute ?: throw Desync()
                    setAttribute(element, attribute)?.let(::bind)
                    reportAttribute(label(element), attribute)
                }
                is RenderEdit.RemoveAttribute -> {
                    val element = siblings.getOrNull(edit.siblingIndex) as? Element ?: throw Desync()
                    val name = edit.name ?: throw Desync()
                    element.attributes.remove(name)
                    changes += RenderChange.AttributeRemoved(label(element), name)
                }
                is RenderEdit.UpdateText -> {
                    val text = siblings.getOrNull(edit.siblingIndex) as? Text ?: throw Desync()
                    val frame = frames.getOrNull(edit.frameIndex) as? RenderFrame.Text ?: throw Desync()
                    text.text = frame.text
                    frame.text?.let(::reportText)
                }
                is RenderEdit.UpdateMarkup -> {
                    ensure(edit.siblingIndex in siblings.indices)
                    val frame = frames.getOrNull(edit.frameIndex) as? RenderFrame.Markup ?: throw Desync()
                    detach(siblings[edit.siblingIndex])
                    siblings[edit.siblingIndex] = Markup(frame.markup).also(::attach)
                    frame.markup?.let { changes += RenderChange.MarkupShown(it) }
                }
                is RenderEdit.StepIn -> {
                    val element = siblings.getOrNull(edit.siblingIndex) as? Element ?: throw Desync()
                    ensure(ancestors.size < MAX_DEPTH)
                    ancestors.addLast(siblings)
                    parent = element.children
                }
                RenderEdit.StepOut -> parent = ancestors.removeLastOrNull() ?: throw Desync()
                is RenderEdit.PermutationListEntry ->
                    (permutation ?: mutableListOf<Pair<Int, Int>>().also { permutation = it }) +=
                        edit.siblingIndex to edit.moveToSiblingIndex
                RenderEdit.PermutationListEnd -> {
                    val moves = permutation ?: throw Desync()
                    permutation = null
                    val from = moves.map { it.first }
                    ensure(from.toSet().size == moves.size && from.toSet() == moves.map { it.second }.toSet())
                    ensure(from.all { it in siblings.indices })
                    val moved = from.map { siblings[it] }
                    moves.forEachIndexed { index, (_, to) -> siblings[to] = moved[index] }
                }
                is RenderEdit.Unknown -> throw Desync()
            }
        }

        private fun describe(edit: RenderEdit) {
            when (edit) {
                is RenderEdit.PrependFrame -> try {
                    report(build(edit.frameIndex))
                } catch (_: Desync) {
                }
                is RenderEdit.RemoveFrame -> changes += RenderChange.Removed
                is RenderEdit.SetAttribute -> (frames.getOrNull(edit.frameIndex) as? RenderFrame.Attribute)
                    ?.let { reportAttribute(null, it) }
                is RenderEdit.RemoveAttribute -> edit.name?.let { changes += RenderChange.AttributeRemoved(null, it) }
                is RenderEdit.UpdateText -> (frames.getOrNull(edit.frameIndex) as? RenderFrame.Text)?.text?.let(::reportText)
                is RenderEdit.UpdateMarkup -> (frames.getOrNull(edit.frameIndex) as? RenderFrame.Markup)?.markup
                    ?.let { changes += RenderChange.MarkupShown(it) }
                else -> Unit
            }
        }

        /** Port of BrowserRenderer.insertFrame: the logical children one reference frame contributes. */
        private fun build(frameIndex: Int): List<Node> =
            mutableListOf<Node>().also { build(frameIndex, ancestors.size, ancestors.isNotEmpty(), it) }

        private fun build(index: Int, depth: Int, insideElement: Boolean, out: MutableList<Node>) {
            ensure(depth < MAX_DEPTH)
            when (val frame = frames.getOrNull(index) ?: throw Desync()) {
                is RenderFrame.Element -> {
                    val end = subtreeEnd(index, frame.subtreeLength, frames.size)
                    val element = Element(frame.name)
                    var child = index + 1
                    while (child < end) {
                        val attribute = frames[child] as? RenderFrame.Attribute ?: break
                        setAttribute(element, attribute)
                        child++
                    }
                    buildRange(child, end, depth + 1, true, element.children)
                    out += element
                }
                is RenderFrame.Text -> out += Text(frame.text)
                is RenderFrame.Markup -> out += Markup(frame.markup)
                is RenderFrame.Component -> out += ComponentSlot(frame.componentId)
                is RenderFrame.Region ->
                    buildRange(index + 1, subtreeEnd(index, frame.subtreeLength, frames.size), depth + 1, insideElement, out)
                is RenderFrame.ElementReferenceCapture -> ensure(insideElement)
                RenderFrame.NamedEvent -> Unit
                is RenderFrame.Attribute, RenderFrame.ComponentReferenceCapture, RenderFrame.ComponentRenderMode,
                is RenderFrame.Unknown -> throw Desync()
            }
        }

        private fun buildRange(start: Int, end: Int, depth: Int, insideElement: Boolean, out: MutableList<Node>) {
            var index = start
            while (index < end) {
                build(index, depth, insideElement, out)
                index = when (val frame = frames[index]) {
                    is RenderFrame.Element -> subtreeEnd(index, frame.subtreeLength, end)
                    is RenderFrame.Component -> subtreeEnd(index, frame.subtreeLength, end)
                    is RenderFrame.Region -> subtreeEnd(index, frame.subtreeLength, end)
                    else -> index + 1
                }
            }
        }

        private fun subtreeEnd(index: Int, length: Int, limit: Int): Int {
            ensure(length >= 1 && length <= limit - index)
            return index + length
        }

        /** Returns the handler to bind when the frame carries one; event attributes never set a DOM attribute. */
        private fun setAttribute(element: Element, frame: RenderFrame.Attribute): Pair<Element, String>? {
            val name = frame.name ?: throw Desync()
            val handler = frame.eventHandlerId
            if (handler == null) {
                if (frame.value == null) element.attributes.remove(name) else element.attributes[name] = frame.value
                return null
            }
            ensure(name.startsWith("on"))
            val eventName = name.substring(2)
            val replaced = element.handlers.put(eventName, handler)
            if (replaced != null && bindings[replaced]?.element === element) bindings.remove(replaced)
            return element to eventName
        }

        private fun bind(target: Pair<Element, String>) {
            val (element, eventName) = target
            val id = element.handlers.getValue(eventName)
            ensure(id !in bindings)
            bindings[id] = Binding(element, eventName)
        }

        private fun attach(node: Node) {
            nodes++
            when (node) {
                is Element -> {
                    node.handlers.keys.forEach { bind(node to it) }
                    node.children.forEach(::attach)
                }
                is ComponentSlot -> attachRoot(node.componentId)
                is Text, is Markup -> Unit
            }
        }

        private fun report(built: List<Node>) {
            for (node in built) when (node) {
                is Element -> {
                    if (node.tag in INTERACTIVE_TAGS || node.handlers.isNotEmpty()) changes += RenderChange.Inserted(label(node))
                    if (node.tag !in SELF_LABELLED_TAGS) report(node.children)
                }
                is Text -> node.text?.let(::reportText)
                is Markup -> node.markup?.let { changes += RenderChange.MarkupShown(it) }
                is ComponentSlot -> Unit
            }
        }

        private fun reportText(text: String) {
            if (text.isNotBlank()) changes += RenderChange.TextShown(text)
        }

        private fun reportAttribute(target: ElementLabel?, frame: RenderFrame.Attribute) {
            val name = frame.name ?: return
            if (frame.eventHandlerId != null) return
            changes += frame.value?.let { RenderChange.AttributeSet(target, name, it) } ?: RenderChange.AttributeRemoved(target, name)
        }

        private fun ensure(condition: Boolean) {
            if (!condition) throw Desync()
        }
    }

    private fun label(element: Element) = ElementLabel(
        tag = element.tag,
        id = element.attributes["id"],
        name = element.attributes["name"],
        type = element.attributes["type"],
        placeholder = element.attributes["placeholder"],
        text = if (element.tag in CONTAINER_TAGS) null else textOf(element),
        disabled = "disabled" in element.attributes,
    )

    /** Visible text of a subtree, including mirrored child components, within a fixed visit budget. */
    private fun textOf(element: Element): String? {
        val text = StringBuilder()
        val pending = ArrayDeque<Node>(element.children.asReversed())
        var visits = 0
        while (pending.isNotEmpty() && visits++ < MAX_LABEL_VISITS && text.length < MAX_LABEL_CHARS) {
            when (val node = pending.removeLast()) {
                is Element -> node.children.asReversed().forEach(pending::addLast)
                is ComponentSlot -> mirrored[node.componentId]?.asReversed()?.forEach(pending::addLast)
                is Text -> text.append(node.text.orEmpty())
                is Markup -> text.append(stripTags(node.markup.orEmpty()))
            }
        }
        return text.toString().replace(WHITESPACE, " ").trim().ifEmpty { null }
    }

    private fun size(node: Node): Int = 1 + ((node as? Element)?.children?.sumOf(::size) ?: 0)

    private fun stripTags(markup: String): String = markup.replace(TAG, "")
        .replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'")
        .replace("&nbsp;", " ").replace("&amp;", "&")

    private companion object {
        const val MAX_DEPTH = 256
        const val MAX_LABEL_VISITS = 256
        const val MAX_LABEL_CHARS = 200
        val INTERACTIVE_TAGS = setOf("a", "button", "form", "input", "select", "textarea", "iframe", "script", "object", "embed")
        val SELF_LABELLED_TAGS = setOf("a", "button", "select", "textarea", "script", "option", "style")
        val CONTAINER_TAGS = setOf("form", "select", "table", "ul", "ol")
        val TAG = Regex("<[^>]*>")
        val WHITESPACE = Regex("\\s+")
    }
}
