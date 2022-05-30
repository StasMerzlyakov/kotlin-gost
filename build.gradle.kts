buildscript {
    allprojects {

        repositories {
            mavenCentral()
            google()
            maven {
                url = uri("https://oss.sonatype.org/content/repositories/snapshots")
            }
        }
    }

    dependencies {
        classpath ("org.jetbrains.kotlin:kotlin-native-utils:${Versions.kotlin}")
        classpath("org.jmailen.gradle:kotlinter-gradle:${Versions.kotlinterGradle}")
    }
}

plugins {
    kotlin("multiplatform") version Versions.kotlin apply false
}

group = "su.ztech"
version = projectVersion
val sonatypeUsername: String? by project