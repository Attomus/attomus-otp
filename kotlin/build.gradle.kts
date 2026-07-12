import io.gitlab.arturbosch.detekt.Detekt
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.tasks.testing.Test

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.detekt)
    alias(libs.plugins.nmcp)
    `maven-publish`
    signing
}

group = "com.attomus"
version = "1.0.2"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
    withSourcesJar()
    withJavadocJar()
}

kotlin {
    jvmToolchain(17)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.withType<Detekt>().configureEach {
    jvmTarget = "17"
}

detekt {
    buildUponDefaultConfig = true
    allRules = false
    config.setFrom(rootProject.files("detekt.yml"))
}

dependencies {
    testImplementation(libs.junit.jupiter.api)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testImplementation(libs.mockk)
    testImplementation("com.code-intelligence:jazzer-junit:0.22.0")
}

val testSourceSet = extensions.getByType(JavaPluginExtension::class.java)
    .sourceSets.getByName("test")

tasks.register<Test>("jazzer") {
    group = "verification"
    description = "Runs the OTP URI parser fuzz target with Jazzer in JUnit fuzzing mode."
    useJUnitPlatform()
    testClassesDirs = testSourceSet.output.classesDirs
    classpath = testSourceSet.runtimeClasspath
    environment("JAZZER_FUZZ", "1")
    filter {
        includeTestsMatching(
            providers.gradleProperty("targetClass")
                .orElse("com.attomus.otp.OTPURIParserFuzzTest")
                .get()
        )
    }
}

publishing {
    publications {
        create<MavenPublication>("release") {
            from(components["java"])
            groupId = "com.attomus"
            artifactId = "attomus-otp-android"
            version = project.version.toString()

            pom {
                name.set("AttomusOTP for Android")
                description.set(
                    "TOTP (RFC 6238) and HOTP (RFC 4226) implementation for Android/JVM. " +
                        "Used by Attomus Signet."
                )
                url.set("https://github.com/attomus/attomus-otp")

                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }

                developers {
                    developer {
                        id.set("attomus")
                        name.set("Attomus Ltd")
                        email.set("hello@attomus.com")
                        url.set("https://attomus.com")
                    }
                }

                scm {
                    connection.set("scm:git:https://github.com/attomus/attomus-otp.git")
                    developerConnection.set("scm:git:https://github.com/attomus/attomus-otp.git")
                    url.set("https://github.com/attomus/attomus-otp")
                    tag.set("v${project.version}")
                }
            }
        }
    }
}

signing {
    val signingKey = providers.gradleProperty("signingKey")
    val signingPassword = providers.gradleProperty("signingPassword")
    useInMemoryPgpKeys(signingKey.orNull, signingPassword.orNull)
    sign(publishing.publications["release"])
}

nmcp {
    publish("release") {
        username = providers.gradleProperty("mavenCentralUsername")
        password = providers.gradleProperty("mavenCentralPassword")
        publicationType = "AUTOMATIC"
    }
}

tasks.register("publishAndReleaseToMavenCentral") {
    group = "publishing"
    description = "Publishes signed release artifacts to Maven Central via the NMCP Central Portal task."
    dependsOn("publishAllPublicationsToCentralPortal")
}
