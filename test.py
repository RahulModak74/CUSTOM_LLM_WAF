#!/usr/bin/env python3
"""
Test script for Nginx Security Server (Python)
"""

import asyncio
import aiohttp
import time
import sys


SERVER = "http://localhost:8080"


async def test_endpoint(session, name, url, headers=None, data=None, expected_status=200):
    """Test an endpoint"""
    print(f"\n{name}...")
    try:
        async with session.request('POST' if data else 'GET', url, headers=headers, data=data) as response:
            status = response.status
            content = await response.text()
            
            if status == expected_status:
                print(f"✅ {name} passed (Status: {status})")
                if "health" in url or "stats" in url:
                    print(f"Response: {content[:200]}...")
            else:
                print(f"❌ {name} failed (Status: {status}, Expected: {expected_status})")
                print(f"Response: {content}")
                
    except Exception as e:
        print(f"❌ {name} failed with error: {e}")


async def main():
    """Run all tests"""
    print("🧪 Testing Nginx Remote Security Server (Python)")
    print("=" * 50)
    
    # Wait for server to start
    print("⏳ Waiting for server to start...")
    await asyncio.sleep(2)
    
    async with aiohttp.ClientSession() as session:
        
        # Test 1: Health Check
        await test_endpoint(
            session, 
            "1. Testing Health Check", 
            f"{SERVER}/health"
        )
        
        # Test 2: Basic Auth Request
        await test_endpoint(
            session,
            "2. Testing Basic Auth Request",
            f"{SERVER}/auth",
            headers={
                "X-Original-Method": "GET",
                "X-Original-URI": "/test",
                "X-Original-Remote-Addr": "192.168.1.100",
                "X-Original-User-Agent": "Mozilla/5.0"
            }
        )
        
        # Test 3: XSS Attack Detection
        await test_endpoint(
            session,
            "3. Testing XSS Attack Detection",
            f"{SERVER}/auth",
            headers={
                "X-Original-Method": "GET",
                "X-Original-URI": "/test?q=<script>alert(1)</script>",
                "X-Original-Remote-Addr": "192.168.1.101",
                "X-Original-User-Agent": "Mozilla/5.0"
            },
            expected_status=403
        )
        
        # Test 4: SQL Injection Detection
        await test_endpoint(
            session,
            "4. Testing SQL Injection Detection",
            f"{SERVER}/auth",
            headers={
                "X-Original-Method": "POST",
                "X-Original-URI": "/login",
                "X-Original-Remote-Addr": "192.168.1.102",
                "X-Original-User-Agent": "Mozilla/5.0"
            },
            data="username=admin' OR '1'='1",
            expected_status=403
        )
        
        # Test 5: Scanner Detection
        await test_endpoint(
            session,
            "5. Testing Scanner Detection",
            f"{SERVER}/auth",
            headers={
                "X-Original-Method": "GET",
                "X-Original-URI": "/test",
                "X-Original-Remote-Addr": "192.168.1.103",
                "X-Original-User-Agent": "sqlmap/1.0"
            },
            expected_status=403
        )
        
        # Test 6: Server Statistics
        await test_endpoint(
            session,
            "6. Getting Server Statistics",
            f"{SERVER}/stats"
        )
        
        # Test 7: Security Status
        await test_endpoint(
            session,
            "7. Getting Security Status",
            f"{SERVER}/status"
        )
        
        print("\n🎉 Testing Complete!")
        
        # Performance test
        print("\n📊 Quick Performance Test...")
        start_time = time.time()
        
        tasks = []
        for i in range(10):
            task = test_endpoint(
                session,
                f"Performance test {i+1}",
                f"{SERVER}/auth",
                headers={
                    "X-Original-Method": "GET",
                    "X-Original-URI": f"/perf{i}",
                    "X-Original-Remote-Addr": f"192.168.1.{i}"
                }
            )
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        end_time = time.time()
        duration_ms = int((end_time - start_time) * 1000)
        avg_time = duration_ms // 10
        
        print(f"⚡ Performance: {avg_time}ms average (10 requests)")
        
        if avg_time < 50:
            print("✅ Performance: Excellent")
        elif avg_time < 100:
            print("✅ Performance: Good")
        else:
            print("⚠️  Performance: Consider optimization")
        
        print("\n🔧 Next Steps:")
        print("   1. Configure your Nginx with auth_request")
        print("   2. Point auth_request to this server")
        print("   3. Monitor logs and statistics")
        print("\n📖 Example Nginx Configuration:")
        print("   location = /auth {")
        print("       internal;")
        print(f"       proxy_pass {SERVER}/auth;")
        print("       proxy_pass_request_body off;")
        print("       proxy_set_header X-Original-URI $request_uri;")
        print("       proxy_set_header X-Original-Method $request_method;")
        print("       proxy_set_header X-Original-Remote-Addr $remote_addr;")
        print("   }")


if __name__ == "__main__":
    asyncio.run(main())
