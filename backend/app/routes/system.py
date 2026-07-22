"""
System-level API endpoints for WAF configuration
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import socket
import subprocess
import requests
from typing import Optional

router = APIRouter()


class DNSVerification(BaseModel):
    domain: str


@router.get("/waf-ip")
async def get_waf_server_ip():
    """
    Get the WAF server's public IP address
    """
    try:
        # Try to get public IP from external service
        response = requests.get('https://api.ipify.org?format=json', timeout=3)
        if response.status_code == 200:
            public_ip = response.json().get('ip')
            return {"public_ip": public_ip, "server_ip": public_ip}
    except:
        pass
    
    # Fallback: get server's hostname IP
    try:
        hostname = socket.gethostname()
        server_ip = socket.gethostbyname(hostname)
        return {"server_ip": server_ip, "public_ip": None}
    except:
        return {"server_ip": "127.0.0.1", "public_ip": None}


@router.post("/verify-dns")
async def verify_dns_configuration(data: DNSVerification):
    """
    Verify if a domain's DNS points to this WAF server
    """
    try:
        # Get WAF server IP
        waf_ip_data = await get_waf_server_ip()
        waf_ip = waf_ip_data.get("public_ip") or waf_ip_data.get("server_ip")
        
        # Resolve the domain
        resolved_ip = socket.gethostbyname(data.domain)
        
        points_to_waf = (resolved_ip == waf_ip)
        
        return {
            "domain": data.domain,
            "resolved_ip": resolved_ip,
            "waf_ip": waf_ip,
            "points_to_waf": points_to_waf,
            "message": "DNS is correctly configured" if points_to_waf else f"DNS points to {resolved_ip} instead of {waf_ip}"
        }
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Could not resolve domain: {data.domain}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DNS verification failed: {str(e)}")


@router.post("/nginx-reload")
async def reload_nginx():
    """
    Reload Nginx configuration
    """
    try:
        result = subprocess.run(
            ["nginx", "-s", "reload"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return {"status": "success", "message": "Nginx reloaded successfully"}
        else:
            raise HTTPException(
                status_code=500,
                detail=f"Nginx reload failed: {result.stderr}"
            )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Nginx reload timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Nginx command not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload Nginx: {str(e)}")
