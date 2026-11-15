import 'dart:async';
import 'package:flet/flet.dart';
import 'package:flutter/services.dart';

class Extension extends FletExtension {
  @override
  FletService? createService(Control control) {
    return control.type == 'SeverVpn' ? VpnService(control: control) : null;
  }
}

class VpnService extends FletService {
  static const methods = MethodChannel('dev.sever/vpn');
  static const events = EventChannel('dev.sever/vpn/events');
  StreamSubscription<dynamic>? subscription;

  VpnService({required super.control});

  @override
  void init() {
    super.init();
    control.addInvokeMethodListener(invoke);
    subscription = events.receiveBroadcastStream().listen((dynamic event) {
      control.triggerEvent('state', Map<String, dynamic>.from(event as Map));
    }, onError: (_) {
      control.triggerEvent('state', {'status': 'error', 'error': 'Native VPN service is unavailable'});
    });
  }

  Future<dynamic> invoke(String name, dynamic args) async {
    try {
      return await methods.invokeMethod<dynamic>(name, args);
    } on PlatformException catch (error) {
      // Never forward native exception details or method arguments (config contains secrets).
      const messages = {
        'permission_denied': 'Android не разрешил переключение VPN. Подтвердите системный запрос. Если для другого VPN включён режим «Постоянная VPN» или блокировка подключений без VPN, отключите его в настройках Android → VPN.',
        'permission_unavailable': 'Не удалось запросить переключение VPN в Android. Проверьте настройки Android → VPN и повторите подключение.',
        'cancelled': 'Подключение VPN отменено.',
      };
      return {'status': 'error', 'error': messages[error.code] ?? 'Native VPN operation failed'};
    }
  }

  @override
  void dispose() {
    subscription?.cancel();
    control.removeInvokeMethodListener(invoke);
    // The foreground service owns the connection, independently of this Dart control.
    super.dispose();
  }
}

