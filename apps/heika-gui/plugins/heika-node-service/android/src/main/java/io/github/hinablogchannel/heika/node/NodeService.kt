package io.github.hinablogchannel.heika.node

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat

/**
 * ノードが動いているあいだのフォアグラウンドサービス。ノードはアプリのプロセスの中のスレッドで動くので、
 * ここではプロセスを生かしておくことと、画面を消しても CPU を眠らせないことと、通知に様子を出すことだけをする。
 * 通知を押すとアプリを開く
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

    /** フォアグラウンドサービスだけではプロセスが生きているだけで、画面を消すと CPU が眠って同期がほぼ止まる */
    private var wakeLock: PowerManager.WakeLock? = null

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
        // 通知を更新するたびにここに来るので、取るのは最初の1回だけ
        if (wakeLock == null) {
            wakeLock = getSystemService(PowerManager::class.java)
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "heika:node")
                .apply { acquire() }
        }
        // プロセスごと止められたら、ノードのスレッドもないので、勝手に始め直さない
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        running = false
        wakeLock?.release()
        wakeLock = null
        super.onDestroy()
    }
}
