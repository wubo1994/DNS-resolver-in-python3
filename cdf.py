import numpy as np  
import matplotlib.mlab as mlab  
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

dataset1 = [154.8, 137.2, 193.2, 1340.1, 2572.4, 480.7, 447.5, 181.3, 1234, 512.6, 196.1, 2084.3, 
            2376.4, 268.3, 2342.3, 443.1, 1722.4, 253.9, 160.3, 499.5, 190.2, 170.7, 647.2, 1087.3, 517.7]
dataset2 = [9.9, 8.6, 8.7, 15.4, 16, 10.8, 6.8, 26.2, 332.7, 9.6, 8.3, 31.8, 20.2, 10.8, 49.2, 9.3,
            1137.5, 7.7, 9.7, 8.9, 315.3, 17.7, 32.6, 43.8, 7.6]
dataset3 = [26.1, 26.7, 37.2, 9.9, 163.6, 370.1, 18, 23.3, 934.7, 18.1, 14.8, 155.7, 206.9, 10.8, 404.8, 150.2,
            1077.2, 13.3, 15.6, 21.7, 25.6, 28.7, 20, 80.4, 33]
plt.hist(dataset1, density=True, cumulative=True, label='CDF DATA', 
         histtype='step', alpha=0.55, color='green')
plt.hist(dataset2, density=True, cumulative=True, label='CDF DATA', 
         histtype='step', alpha=0.55, color='blue')
plt.hist(dataset3, density=True, cumulative=True, label='CDF DATA', 
         histtype='step', alpha=0.55, color='purple')
plt.xlabel("Query time (msec)")
plt.ylabel("Probability")
cmap = plt.get_cmap('jet')
low = cmap(0.5)
medium =cmap(0.25)
high = cmap(0.8)
handles = [Rectangle((0,0),1,1,color=c,ec="k") for c in [low,medium, high]]
labels= ["mydig","stonybrook.edu", "8.8.8.8"]
plt.legend(handles, labels)
plt.show()
