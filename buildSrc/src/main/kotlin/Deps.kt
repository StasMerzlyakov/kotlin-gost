/*
 * Created by Stanislav Merzlyakov
 * st.merzlyakov@yandex.ru
 *  in May-2022.
 */


object Versions {
    const val kotlinCoroutines = "1.6.1"
    const val kotlin = "1.6.21"
    const val kotlinterGradle = "3.8.0"
    const val kotlinBignum = "0.3.5-SNAPSHOT"
}

const val projectVersion = "1.0-SNAPSHOT"

object Deps {

    object Common {
        const val stdLib = "stdlib-common"
        const val test = "test"
        const val testAnnotation = "test-annotations-common"
        const val coroutines = "org.jetbrains.kotlinx:kotlinx-coroutines-core:${Versions.kotlinCoroutines}"
        const val testCoroutines = "org.jetbrains.kotlinx:kotlinx-coroutines-test:${Versions.kotlinCoroutines}"
        const val bignum = "com.ionspin.kotlin:bignum:${Versions.kotlinBignum}"
    }

    object Js {
        const val stdLib = "stdlib-js"
        const val test = "test-js"
        const val coroutines = "org.jetbrains.kotlinx:kotlinx-coroutines-core:${Versions.kotlinCoroutines}"
    }

    object Jvm {
        const val stdLib = "stdlib-jdk8"
        const val test = "test"
    }

    object iOs {
        const val coroutines = "org.jetbrains.kotlinx:kotlinx-coroutines-core-native:${Versions.kotlinCoroutines}"
    }

    object Native {
        const val coroutines = "org.jetbrains.kotlinx:kotlinx-coroutines-core:${Versions.kotlinCoroutines}"
    }

}

object PluginsDeps {
    const val multiplatform = "multiplatform"
    const val node = "com.github.node-gradle.node"
    const val mavenPublish = "maven-publish"
    const val signing = "signing"
    const val kotlinter = "org.jmailen.kotlinter"
}

