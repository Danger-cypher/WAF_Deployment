from app.services.stats_calculator import _get_total_nginx_requests, get_total_blocked_count
from datetime import datetime
print("Now:", datetime.now())
print("Total 24h:", _get_total_nginx_requests(24))
print("Total 168h:", _get_total_nginx_requests(168))
print("Total None:", _get_total_nginx_requests(None))
print("Blocked 24h:", get_total_blocked_count(24))
