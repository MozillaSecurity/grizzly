#!/usr/bin/env python
# pylint: disable=missing-docstring
import argparse


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Android Asset Packaging Tool ... Well really it's Fake AAPT")
    parser.add_argument(
        "cmd",
        help="ADB command to execute")
    parser.add_argument(
        "extra", action="append", default=list(), nargs=argparse.REMAINDER,
        help="Extra args")
    return parser.parse_args(argv)


def main(argv=None):
    parse_args(argv)
    print("package: name='org.mozilla.fennec_aurora' versionCode='2015624653' versionName='68.0a1' platformBuildVersionName=''")
    print("install-location:'internalOnly'")
    print("sdkVersion:'16'")
    print("targetSdkVersion:'28'")
    print("uses-permission: name='android.permission.READ_SYNC_SETTINGS'")
    print("uses-permission: name='org.mozilla.fennec_aurora_fxaccount.permission.PER_ACCOUNT_TYPE'")
    print("uses-permission: name='com.google.android.c2dm.permission.RECEIVE'")
    print("uses-permission: name='org.mozilla.fennec_aurora.permission.C2D_MESSAGE'")
    print("uses-permission: name='com.samsung.android.providers.context.permission.WRITE_USE_APP_FEATURE_SURVEY'")
    print("uses-permission: name='android.permission.MODIFY_AUDIO_SETTINGS'")
    print("application-label:'Firefox Nightly'")
    print("application-label-en-GB:'Firefox Nightly'")
    print("application-icon-240:'res/mipmap-anydpi-v26/ic_launcher.xml'")
    print("application-icon-320:'res/mipmap-anydpi-v26/ic_launcher.xml'")
    print("application-icon-480:'res/mipmap-anydpi-v26/ic_launcher.xml'")
    print("application-icon-640:'res/mipmap-anydpi-v26/ic_launcher.xml'")
    print("application-icon-65534:'res/mipmap-anydpi-v26/ic_launcher.xml'")
    print("application-icon-65535:'res/mipmap-anydpi-v26/ic_launcher.xml'")
    print("application: label='Firefox Nightly' icon='res/mipmap-anydpi-v26/ic_launcher.xml'")
    print("application-debuggable")
    print("feature-group: label=''")
    print("  uses-gl-es: '0x20000'")
    print("  uses-feature-not-required: name='android.hardware.audio.low_latency'")
    print("  uses-feature-not-required: name='android.hardware.camera'")
    print("  uses-feature-not-required: name='android.hardware.camera.any'")
    print("  uses-feature-not-required: name='android.hardware.camera.autofocus'")
    print("  uses-feature-not-required: name='android.hardware.location'")
    print("  uses-feature-not-required: name='android.hardware.location.gps'")
    print("  uses-feature-not-required: name='android.hardware.microphone'")
    print("  uses-feature-not-required: name='android.hardware.nfc'")
    print("  uses-feature: name='android.hardware.touchscreen'")
    print("  uses-feature: name='android.hardware.location.network'")
    print("  uses-implied-feature: name='android.hardware.location.network' reason='requested android.permission.ACCESS_COARSE_LOCATION permission'")
    print("  uses-feature: name='android.hardware.wifi'")
    print("  uses-implied-feature: name='android.hardware.wifi' reason='requested android.permission.ACCESS_WIFI_STATE permission, and requested android.permission.CHANGE_WIFI_STATE permission'")
    print("provides-component:'app-widget'")
    print("main")
    print("other-activities")
    print("other-receivers")
    print("other-services")
    print("supports-screens: 'small' 'normal' 'large' 'xlarge'")
    print("supports-any-density: 'true'")
    print("locales: '--_--' 'ca' ' 'en-GB' 'zh-HK' 'zh-CN' 'en-IN' 'pt-BR' 'es-US' 'pt-PT' 'en-AU' 'zh-TW'")
    print("densities: '120' '160' '240' '320' '480' '640' '65534' '65535'")
    print("native-code: 'x86'")


if __name__ == "__main__":
    exit(main())
