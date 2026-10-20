plugins {
    kotlin("jvm") version "2.4.21"
}

group = "com.gdssecurity"
version = "1.1-native-ws"

// Use the host JDK while restricting bytecode and JDK APIs to Java 21.
kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21
        freeCompilerArgs.add("-Xjdk-release=21")
    }
}

// No Java sources, but the Kotlin plugin requires matching Java and Kotlin JVM targets.
tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.msgpack:msgpack-core:0.9.3")
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")
    implementation("org.json:json:20220924")
    testImplementation(platform("org.junit:junit-bom:5.13.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.7")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    dependsOn(tasks.jar)
    systemProperty("btp.jar", tasks.jar.get().archiveFile.get().asFile.absolutePath)
    systemProperty("java.awt.headless", "true")
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes("Main-Class" to "com.gdssecurity.BlazorTrafficProcessor")
    }
    from({
        configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) }
    })
}
