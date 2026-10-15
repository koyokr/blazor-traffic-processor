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

package com.gdssecurity.messages

import org.msgpack.value.ImmutableArrayValue
import org.msgpack.value.ImmutableMapValue
import org.msgpack.value.ImmutableValue

/** Complete, immutable protocol values. Parsing and serialization are separate operations. */
sealed interface HubMessage {
    data class Invocation(
        val headers: ImmutableMapValue,
        val invocationId: String?,
        val target: String,
        val arguments: ImmutableArrayValue,
        val streamIds: ImmutableArrayValue?,
        val streaming: Boolean = false,
    ) : HubMessage

    data class StreamItem(
        val headers: ImmutableMapValue,
        val invocationId: String,
        val item: ImmutableValue,
    ) : HubMessage

    data class Completion(
        val headers: ImmutableMapValue,
        val invocationId: String,
        val result: CompletionResult,
    ) : HubMessage

    data class CancelInvocation(val headers: ImmutableMapValue, val invocationId: String) : HubMessage
    data object Ping : HubMessage
    data class Close(val error: String?, val allowReconnect: Boolean?) : HubMessage
    data class Ack(val sequenceId: Long) : HubMessage
    data class Sequence(val sequenceId: Long) : HubMessage
}

sealed interface CompletionResult {
    data class Error(val message: String) : CompletionResult
    data object Void : CompletionResult
    data class Value(val value: ImmutableValue) : CompletionResult
}
