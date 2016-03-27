                           From AArch32 to AArch64 and back
                                                   deroko of ARTeam

To compile and run:

change NDKROOT64 in Makefile to point to your NDK folder
install pyelftools from https://github.com/eliben/pyelftools

# make
# adb push switch /data/local/tmp
# adb shell
shell@zeroflte:/ $ /data/local/tmp/switch                                      
tada - executed as AArch64 from AArch32
And I'm back baby...
shell@zeroflte:/ $ 

That should be it, for more info check switch.txt
