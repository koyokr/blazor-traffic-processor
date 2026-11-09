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
package com.gdssecurity.helpers

object BTPConstants {
    const val EXTENSION_NAME = "BlazorTrafficProcessor"
    const val CAPTION = "BTP"
    val VERSION: String = BTPConstants::class.java.`package`.implementationVersion ?: "dev"
    val LOADED_LOG_MSG = "Loaded $EXTENSION_NAME v$VERSION"
    val UNLOADED_LOG_MSG = "Unloaded $EXTENSION_NAME v$VERSION"
}
