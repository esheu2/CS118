import numpy as np
import matplotlib.pyplot as plot

#1000111001
time = np.arange(0, 11, 1.05)
amplitude = [1,0,0,0,1,1,1,0,0,1,1]

plot.plot(time, amplitude, drawstyle='steps-post')
sampling = np.arange(0.5, 11, 1.05)
for s in sampling:
    plot.axvline(x=s, linestyle=':', color='green')
plot.title('Waveform')
plot.xlabel('Time')
plot.ylabel('Voltage')
plot.grid(True, which='both')
plot.axhline(y=0, color='k')
plot.show()
plot.show()
