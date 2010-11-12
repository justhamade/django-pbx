from pytz import timezone
import datetime, time, os
import md5

import sys, string
import shutil

from wikipbx import settings

# TODO: should not be hardcoded to a path that only works on *nix
def make_tts_file(tts_string, tts_voice=None, cache=True):
    static_tts_engine = get_static_tts_engine()
    m = md5.new()
    m.update(tts_string)
    hexdigest = m.hexdigest()
    tts_dest = os.path.join("/tmp/wikipbx/tts")
    if not os.path.exists(tts_dest):
        os.makedirs(tts_dest)
    file2write = "%s/%s-%s.wav" % (tts_dest, hexdigest, tts_voice)
    if cache and os.path.exists(file2write):
        return file2write

    if static_tts_engine == "festival":
        if make_tts_file_festival(tts_string, file2write):
            return file2write
        else:
            raise Exception("Error calling festival.  File2write: %s" %
                            file2write)
    else:
        if tts_voice:
            cmd = 'swift -n %s "%s" -o %s' % (tts_voice,
                                              tts_string,
                                              file2write)
        else:
            cmd = 'swift "%s" -o %s' % (tts_string,
                                        file2write)

    os.system(cmd)

    # was the file created?
    if not os.path.exists(file2write):
        raise Exception("Failed to create tts audio file")
    
    return file2write

def make_tts_file_festival(tts_string, file2write):

    cmd = "/usr/bin/text2wave -scale 2 -o %s" % (file2write)
    fd = os.popen(cmd, 'w')
    fd.write(tts_string)
    exit_code = fd.close()
    if exit_code is not None and exit_code != 0:
        raise Exception("Command failed: %s" % cmd)
    return samplefreq8k( file2write )

def runCommand(command, reqSuccess=True, showDebug=False):
    if showDebug:
        print command
    returncode = os.system(command)
    if reqSuccess:
        if returncode is not None and returncode != 0:
            raise "Error, command %s failed" % command

def samplefreq8k(origwav):

    """ Converts the given wave file to have a sample frequency
    of 8 kHZ """

    # copy orig to temp
    tempWavFile = getTempFile("wav")
    shutil.copy(origwav, tempWavFile)

    # convert temp to be 8kz, and overwrite orig
    cmd = "sox %s -r 8000 %s" % (tempWavFile, origwav)
    runCommand(cmd)

    # delete temp
    os.remove(tempWavFile)
    
    return origwav

def getTempDir():
    default_temp = "/tmp"
    if os.path.exists(default_temp):
        return default_temp
    else:
        return "/tmp"

def getTempFile(ext="txt"):
    tempdir = getTempDir()
    # eg 1112925564.7757831
    thetime = str(time.time())
    numloops = 0

    import random
    rand_num = random.randint(0,100000000)
    tempfile = "%s/%s.%s" % (tempdir, rand_num, ext)    
    return tempfile

def get_static_tts_engine():
    """
    check settings.py and see if there is a variable set.
    if so, return it.  otherwise return default (cepstral)
    """
    if settings.__dict__.has_key("STATIC_TTS_ENGINE"):
        return settings.STATIC_TTS_ENGINE
    else:
        return "cepstral"


if __name__=="__main__":
    print make_tts_file("hello world, again")
