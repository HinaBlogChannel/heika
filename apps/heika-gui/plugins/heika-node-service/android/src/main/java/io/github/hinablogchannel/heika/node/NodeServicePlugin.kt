package io.github.hinablogchannel.heika.node

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin

@InvokeArg
class NoticeArgs {
    var text: String = ""
}

/** アプリの本体（Rust）から、ノードのサービスを始めて、通知を変えて、止める */
@TauriPlugin
class NodeServicePlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun start(invoke: Invoke) {
        // Android 13 からは、通知を出すのに許可が要る。許可がなくてもサービスは動き、通知が出ないだけ
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }
        ContextCompat.startForegroundService(activity, intent(invoke))
        invoke.resolve()
    }

    @Command
    fun update(invoke: Invoke) {
        if (NodeService.running) {
            activity.startService(intent(invoke))
        }
        invoke.resolve()
    }

    @Command
    fun stop(invoke: Invoke) {
        // 止まり終える（onDestroy）より先に来た通知の更新で、また始めないように、ここで印を下ろす
        NodeService.running = false
        activity.stopService(Intent(activity, NodeService::class.java))
        invoke.resolve()
    }

    private fun intent(invoke: Invoke): Intent {
        val args = invoke.parseArgs(NoticeArgs::class.java)
        return Intent(activity, NodeService::class.java).putExtra(NodeService.TEXT, args.text)
    }
}
