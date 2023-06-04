import matplotlib.pyplot as plt

f = open('flag', 'r')
lines = f.read().splitlines()
f.close()

lats = []
longs = []

for line in lines:
    if 'AFSK' in line:
        continue
    lat_deg = float(line[1:3])
    lat_min = float(line[3:8])
    long_deg = float(line[11:13])
    long_min = float(line[13:18])
    print('lat_deg: ' + str(lat_deg), ' lat_min: ' + str(lat_min) + ', long_deg: ' + str(long_deg) + ', long_min: ' + str(long_min))
    lat = lat_deg + (lat_min/60.0)
    if lat > 43.764:
        lat -= 0.0065
    long = long_deg + (long_min/60.0)
    longs.append(long)
    lats.append(lat)

plt.scatter(longs, lats, s=14)
plt.show()

# The flag is written in the plot, the spacing is a little wonky and you have to piece it together
# DANTE{FLAG_REPORTING_SYSTEM}
