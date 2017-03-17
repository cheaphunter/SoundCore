//// ALSA API emulator ////

var rate = 0;
var channels = 2; // stereo
var format = 2; // SND_PCM_FORMAT_S16_LE

var dwCallback = null;

var alsa_lib = "libasound.so.2.0.0";
var libc = "libc-2.23.so";
var pulse_simple_lib = "libpulse-simple.so.0.1.0";

// int snd_pcm_hw_params_set_format (snd_pcm_t *pcm, snd_pcm_hw_params_t *params, snd_pcm_format_t val)
var a = Module.findExportByName(alsa_lib, "snd_pcm_hw_params_set_format");
if (a) {
    Interceptor.attach(a, {
        onEnter: function (args) {
            // SND_PCM_FORMAT_S16_LE == 2, SND_PCM_FORMAT_S32_LE == 10
            format = args[2].toInt32();
            console.log("ALSA> PCM format is " + format);
            send(['format', format]);
        }
    });
}

// snd_pcm_hw_params_set_rate_near (snd_pcm_t *pcm, snd_pcm_hw_params_t *params, unsigned int *val, int *dir)
a = Module.findExportByName(alsa_lib, "snd_pcm_hw_params_set_rate_near");
if (a) {
    Interceptor.attach(a, {
        onEnter: function (args) {
            rate = Memory.readUInt(args[2]);
            console.log("ALSA> Rate is " + rate);
            send(['rate', rate]);
        }
    });
}

// snd_pcm_hw_params_set_rate (snd_pcm_t *pcm, snd_pcm_hw_params_t *params, unsigned int *val, int *dir)
a = Module.findExportByName(alsa_lib, "snd_pcm_hw_params_set_rate");
if (a) {
    Interceptor.attach(a, {
        onEnter: function (args) {
            rate = Memory.readUInt(args[2]);
            console.log("ALSA> Rate is " + rate);
            send(['rate', rate]);
        }
    });
}

// int snd_pcm_hw_params_set_channels (snd_pcm_t *pcm, snd_pcm_hw_params_t *params, unsigned int val)
a = Module.findExportByName(alsa_lib, "snd_pcm_hw_params_set_channels");
if (a) {
    Interceptor.attach(a, {
        onEnter: function (args) {
            channels = args[2].toInt32();
            console.log("JS> Channel count is " + channels);
            send(['channels', channels]);
        }
    });
}

// snd_pcm_sframes_t snd_pcm_writei (snd_pcm_t *pcm, const void *buffer, snd_pcm_uframes_t size)
var snd_pcm_writei_addr = Module.findExportByName(alsa_lib, "snd_pcm_writei");
if (snd_pcm_writei_addr) {
    Interceptor.replace(snd_pcm_writei_addr, new NativeCallback(function (pcm, buffer, size) {
        var bytes_per_frame = 2;
        if (format == 2) {
            bytes_per_frame = 2;
        } else if (format == 10) {
            bytes_per_frame = 2;
        } else {
            console.log("JS> Problem in calculating write buffer size");
        }

        var length = size * bytes_per_frame * channels;
        var data = Memory.readByteArray(buffer, length);
        send(['pcm', "dummy"], data);
        return size;
    }, 'long', ['pointer', 'pointer', 'long']));
}

// int snd_pcm_recover(snd_pcm_t *pcm, int err, int silent)
var snd_pcm_recover_addr = Module.findExportByName(alsa_lib, "snd_pcm_recover");
if (snd_pcm_recover_addr) {
    Interceptor.replace(snd_pcm_recover_addr, new NativeCallback(function (pcm, err, silent) {
        return 0;  // "error" handled succesfully
    }, 'int', ['pointer', 'int', 'int']));
}

// int snd_pcm_wait(snd_pcm_waitsnd_pcm_t * pcm, int timeout)
var snd_pcm_wait_addr = Module.findExportByName(alsa_lib, "snd_pcm_wait");
if (snd_pcm_wait_addr) {
    Interceptor.replace(snd_pcm_wait_addr, new NativeCallback(function (pcm, timeout) {
        return 1; // PCM stream is "always" ready for I/O
    }, 'int', ['pointer', 'int']));
}

// void exit(int status), hook exit to ensure that all asynchronous "send" calls have been completed
var exit_addr = Module.findExportByName(libc, "exit");
if (exit_addr) {
    console.log("JS> Trapped exit successfully!");
    Interceptor.replace(exit_addr, new NativeCallback(function (status) {
        console.log("JS> Application is exiting!");
        send(['exit', "dummy"]);
        // block to ensure that all other send calls have been complete, send calls are procesed in fifo fashion
        recv('exit_ack', function onMessage(msg) { console.log("JS> Ping-pong in exit is done!"); }).wait();
        Thread.sleep(1);
    }, 'void', ['int']));
}

//// PulseAudio Simple API emulator ////

// pa_simple *pa_simple_new (const char *server, const char *name,
//     pa_stream_direction_t dir, const char *dev, const char *stream_name, const
//     pa_sample_spec *ss, const pa_channel_map *map, const pa_buffer_attr *attr,
//     int *error)
a = Module.findExportByName(pulse_simple_lib, "pa_simple_new");
if (a) {
    Interceptor.attach(a, {
        onEnter: function (args) {
            var p = args[5]; // pa_sample_spec *ss
            format = Memory.readUInt(p);
            rate = Memory.readU16(p.add(4));
            channels = Memory.readU8(p.add(8));
            console.log("PA> PCM format is " + format);
            console.log("PA> Rate is " + rate);
            console.log("PA> Channel count is " + channels);
        }
    });
}

// int pa_simple_write(pa_simple *p, const void*data, size_t length, int *rerror)
var pa_simple_write_addr = Module.findExportByName(pulse_simple_lib, "pa_simple_write");
if (pa_simple_write_addr) {
    Interceptor.replace(pa_simple_write_addr, new NativeCallback(function (p, data, length, rerror) {
        var buf = Memory.readByteArray(data, length);
        send(['pcm', "dummy"], buf);
        return 0;
    }, 'int', ['pointer', 'pointer', 'long', 'pointer']));
}

//// PulseAudio API emulator ////

// int pa_stream_write(pa_stream *s, const void *data, size_t length, pa_free_cb_t free_cb, int64_t offset, pa_seek_mode_t seek)
/* var pa_stream_write_addr = Module.findExportByName(null, "pa_stream_write");
if (pa_stream_write_addr) {
    Interceptor.attach(pa_stream_write_addr, {
        onEnter: function (args) {
            var length = args[2].toInt32();
            var data = args[1];
            var buf = Memory.readByteArray(data, length);
            send(['pcm', "dummy"], buf);
        }
    });
} */

// pa_stream *pa_stream_new(pa_context *c, const char *name, const pa_sample_spec *ss, const pa_channel_map *map)
var a = Module.findExportByName(null, "pa_stream_new");
if (a) {
    Interceptor.attach(a, {
        onEnter: function (args) {
            var p = args[2]; // pa_sample_spec *ss
            format = Memory.readUInt(p);
            rate = Memory.readU16(p.add(4));
            channels = Memory.readU8(p.add(8));
            console.log("PA> PCM format is " + format);
            console.log("PA> Rate is " + rate);
            console.log("PA> Channel count is " + channels);
        }
    });
}

var pa_stream_write_addr = Module.findExportByName(null, "pa_stream_write");
if (pa_stream_write_addr) { // enabling this works for cmus
    Interceptor.replace(pa_stream_write_addr, new NativeCallback(function (s, data, length, free_cb, offset, seek) {
        var buf = Memory.readByteArray(data, length);
        send(['pcm', "dummy"], buf);
        return 0;
    }, 'int', ['pointer', 'pointer', 'long', 'pointer', 'long', 'pointer']));
}

// the following commented out code causes lot of problems!

/* // enum pa_context_get_state(pa_context *c)
var pa_context_get_state_arr = Module.findExportByName(null, "pa_context_get_state");
if (pa_context_get_state_arr) {
    Interceptor.replace(pa_context_get_state_arr, new NativeCallback(function (c) {
        console.log("context!");
        return 5; // PA_CONTEXT_READY
    }, 'int', ['pointer']));
}

// enum pa_stream_get_state(pa_stream *s)
var pa_stream_get_state_arr = Module.findExportByName(null, "pa_stream_get_state");
if (pa_stream_get_state_arr) {
    Interceptor.replace(pa_stream_get_state_arr, new NativeCallback(function (s) {
        console.log("stream!");
        return 2; // PA_STREAM_READY
    }, 'int', ['pointer']));
}

// int pa_mainloop_iterate(pa_mainloop *m, int block, int *retval)
/* var pa_mainloop_iterate_addr = Module.findExportByName(null, "pa_mainloop_iterate");
console.log(pa_mainloop_iterate_addr);
if (pa_mainloop_iterate_addr) {
    Interceptor.replace(pa_mainloop_iterate_addr, new NativeCallback(function (m, block, retval) {
        return 0; // success
    }, 'int', ['pointer', 'int', 'pointer']));
} */

//// SDL API emulation ////

// int SDL_OpenAudio(SDL_AudioSpec* desired, SDL_AudioSpec* obtained), https://wiki.libsdl.org/SDL_AudioSpec, https://wiki.libsdl.org/SDL_AudioSpec
a = Module.findExportByName("libSDL-1.2.so.0.11.4", "SDL_OpenAudio");
if (a) {
    Interceptor.attach(a, {
        onEnter: function (args) {
            var p = args[0]; // SDL_AudioSpec*
            rate = Memory.readUInt(p);
            format = Memory.readU16(p.add(4));
            if (format == 0x8010) { // AUDIO_U16SYS
                format = 3; // PulseAudio compatible
            }
            channels = Memory.readU8(p.add(6));
            console.log("SDL> PCM format is " + format);
            console.log("SDL> Rate is " + rate);
            console.log("SDL> Channel count is " + channels);
        }
    });
}


//// Win32 sound API emulation (unstable and crash prone) ////

a = Module.findExportByName(null, "waveOutOpen");
if (a) {
    Interceptor.attach(a, {
        onEnter: function (args) {
            var p = args[2]; // LPCWAVEFORMATEX lpFormat
            channels = Memory.readU16(p.add(2));
            rate = Memory.readUInt(p.add(4));
            // console.log("Win32> PCM format is " + format);
            // console.log("Win32> Rate is " + rate);
            // console.log("Win32> Channel count is " + channels);
            var dwFlags = args[5];
            dwCallback = args[3];
            // console.log(dwCallback);
        }
    });
}

// /mingw64/x86_64-w64-mingw32/include/mmsystem.h
a = Module.findExportByName(null, "waveOutWrite");
if (a) {
    Interceptor.replace(a, new NativeCallback(function (hWaveOut, header, uSize) {
        var lpData = Memory.readPointer(header)
        var dwBufferLength = Memory.readUInt(header.add(8))
        var buf = Memory.readByteArray(lpData, dwBufferLength);
        var dwFlags = Memory.readUInt(header.add(24)) // DWORD
        console.log(dwBufferLength);
        dwFlags = dwFlags | 0x1;
        dwCallback = 0x11223344;  // magic value
        Memory.writeU32(header.add(24), dwFlags)
        send(['pcm', "dummy"], buf);
        return 0;
    }, 'int', ['pointer', 'pointer', 'int']));
}

// DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
a = Module.findExportByName(null, "WaitForSingleObject");
if (a) {
    var WaitForSingleObject = new NativeFunction(a, 'int', ['pointer', 'int']);
    Interceptor.replace(a, new NativeCallback(function (hHandle, period) {
        // console.log(hHandle);
        if (dwCallback == 0x11223344) {
            console.log(hHandle);
            return 0;  // nop out
        } else {
            console.log("Original WaitForSingleObject executing!");
            return WaitForSingleObject(hHandle, period);
        }
    }, 'int', ['pointer', 'int']));
}

// vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
