# MTK SU

MTK SU is a LPE for CVE-2020-0069. This exploit was tested on a TCL LX A502DL
with a MediaTek MT6739 SoC running Android 8.1.0.

## Build

```
mkdir build
cd build
export ANDROID_NDK=<path_to_android_ndk>
cmake -DCMAKE_TOOLCHAIN_FILE="${ANDROID_NDK?}/build/cmake/android.toolchain.cmake" -DANDROID_ABI="armeabi-v7a" -DANDROID_PLATFORM=android-21 ../
cmake --build .
```
