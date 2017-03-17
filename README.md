### SoundCore / AudioShark

Frida application for hooking / debugging sound API functions.

* Developed using Frida 9.1.23 on 64-bit Fedora 24.

* Tested with 64-bit mpg123 1.24.0 with ALSA and PulseAudio outputs.

* Tested with CMus, March 2017 version from Git repository.

#### Usage

Install Frida using `pip install --user frida` command.

Run `./AudioShark.py -h` to see usage instructions.

Run `play -t raw -r 22.05k -e signed -b 16 -c 1 output.pcm.frida` to play
captured audio output. `ffplay -f s16le -ar 48k -ac 2 output.pcm.frida` can
also be used.

#### Issues

* Interception of `pa_stream_write` works but replacement doesn't with ffplay /
  mpg123 with SDL output. See `notes.txt` for some details.

#### Notes

* mpg123 can switch between different audio output sub-systems easily, use
  `./configure --with-default-audio=sdl` to use SDL, for example.

#### Resources

* https://www.mpg123.de/cgi-bin/scm/mpg123/trunk/src/libout123/modules/alsa.c

* https://www.mpg123.de/cgi-bin/scm/mpg123/trunk/src/libout123/modules/pulse.c

* https://www.mpg123.de/cgi-bin/scm/mpg123/trunk/src/libout123/modules/sdl.c

* https://www.mpg123.de/cgi-bin/scm/mpg123/trunk/src/libout123/modules/win32.c

* https://github.com/cmus/cmus/blob/master/op/alsa.c

* https://github.com/cmus/cmus/blob/master/op/pulse.c

* https://github.com/FFmpeg/FFmpeg/blob/master/ffplay.c

* https://fossies.org/linux/SDL2/src/audio/SDL_audio.c

* https://fossies.org/linux/SDL2/src/audio/pulseaudio/SDL_pulseaudio.c

* [Nine different audio encoders 100-pass recompression test](http://bernholdtech.blogspot.in/2013/03/Nine-different-audio-encoders-100-pass-recompression-test.html)

#### Credits

* Ole André Vadla Ravnås for all the help.

* http://www.noiseaddicts.com for the music samples.
