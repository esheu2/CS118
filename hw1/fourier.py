import numpy as np
import matplotlib.pyplot as plot


time = np.arange(0, 13/12, 1/12);
amplitude = 2*np.sin(2*3.14*time)+(2/3)*np.sin(6*3.14*time)+(2/5)*np.sin(10*3.14*time)
amplitude_low_pass = 2*np.sin(2*3.14*time)+(2/3)*np.sin(6*3.14*time)

plot.plot(time, amplitude)
plot.plot(time, amplitude_low_pass)
plot.title('Sine wave')
plot.xlabel('Time')
plot.ylabel('Amplitude')
plot.grid(True, which='both')
plot.axhline(y=0, color='k')
plot.show()
plot.show()
