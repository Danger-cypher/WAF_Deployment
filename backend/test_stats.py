from app.services.stats_calculator import calculate_stats, get_top_ips
from datetime import datetime
print("Now:", datetime.now())
print("Stats 24h:", calculate_stats(24))
print("Stats 168h:", calculate_stats(168))
print("Top IPs:", get_top_ips(5, 24))
