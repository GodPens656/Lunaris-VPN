package dev.sever.vpn

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/** A dedicated activity keeps VPN consent independent of the WebView lifecycle. */
class VpnPermissionActivity : Activity() {
    companion object {
        private var completion: ((Boolean) -> Unit)? = null
        fun cancel() { completion = null }
        fun launch(activity: Activity, intent: Intent, callback: (Boolean) -> Unit) {
            completion?.invoke(false)
            completion = callback
            activity.startActivity(Intent(activity, VpnPermissionActivity::class.java).putExtra("consent", intent))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) {
            @Suppress("DEPRECATION")
            val consent = intent.getParcelableExtra<Intent>("consent")
            if (consent == null) { finishResult(false); return }
            @Suppress("DEPRECATION")
            startActivityForResult(consent, 1)
        }
    }

    @Deprecated("Android activity result compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1) finishResult(resultCode == RESULT_OK)
    }

    private fun finishResult(granted: Boolean) {
        val callback = completion
        completion = null
        callback?.invoke(granted)
        finish()
    }
}
