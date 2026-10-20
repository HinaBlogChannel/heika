package io.github.hinablogchannel.heika.node

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

/**
 * ノードが動いているあいだのフォアグラウンドサービス。ノードはアプリのプロセスの中のスレッドで動くので、
 * ここではプロセスを生かしておくことと、通知に様子を出すことだけをする。通知を押すとアプリを開く
 */
class NodeService : Service() {
    companion object {
        const val TEXT = "text"
        private const val CHANNEL = "node"
        private const val NOTIFICATION = 1

        /** 始めてから止めるまで。止めたあとに来た通知の更新で、また始めてしまわないように */
        @Volatile
        var running = false
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        running = true
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, "ノード", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = packageManager.getLaunchIntentForPackage(packageName)
        val notification = NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle("heika ノード")
            .setContentText(intent?.getStringExtra(TEXT) ?: "")
            .setSmallIcon(applicationInfo.icon)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(
                PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE)
            )
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION, notification)
        }
        // プロセスごと止められたら、ノードのスレッドもないので、勝手に始め直さない
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        running = false
        super.onDestroy()
    }
}
