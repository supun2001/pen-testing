"""
Auth0 React 2.6.0 Security Testing Script
WARNING: Only use on applications you have authorization to test
"""

import requests
import json
import base64
import jwt
import time
import urllib.parse
from datetime import datetime
from typing import Dict, List, Tuple
import argparse
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

class Auth0SecurityTester:
    def __init__(self, config: Dict):
        self.domain = config['domain']
        self.client_id = config['client_id']
        self.redirect_uri = config['redirect_uri']
        self.target_url = config.get('target_url', '')
        self.api_url = config.get('api_url', '')
        self.results = []
        self.session = requests.Session()
        
    def log(self, test: str, status: str, details: str):
        """Log test results with color coding"""
        result = {
            'test': test,
            'status': status,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.results.append(result)
        
        color = {
            'VULNERABLE': Fore.RED,
            'WARNING': Fore.YELLOW,
            'SECURE': Fore.GREEN,
            'INFO': Fore.CYAN,
            'ERROR': Fore.MAGENTA
        }.get(status, Fore.WHITE)
        
        print(f"{color}[{status}] {test}: {details}{Style.RESET_ALL}")
    
    def test_open_redirect(self):
        """Test for open redirect vulnerabilities"""
        print(f"\n{Fore.CYAN}=== Testing Open Redirect ==={Style.RESET_ALL}")
        
        malicious_uris = [
            'https://evil.com',
            'https://evil.com/callback',
            'http://localhost@evil.com',
            '//evil.com',
            'javascript:alert(1)'
        ]
        
        for uri in malicious_uris:
            auth_url = f"https://{self.domain}/authorize?" + urllib.parse.urlencode({
                'client_id': self.client_id,
                'redirect_uri': uri,
                'response_type': 'code',
                'scope': 'openid profile email'
            })
            
            try:
                response = self.session.get(auth_url, allow_redirects=False, timeout=10)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if uri in location or 'evil.com' in location:
                        self.log('Open Redirect', 'VULNERABLE', 
                               f'Redirect to {uri} was accepted')
                    else:
                        self.log('Open Redirect', 'SECURE', 
                               f'Redirect to {uri} was blocked')
                else:
                    self.log('Open Redirect', 'INFO', 
                           f'No redirect for {uri} (Status: {response.status_code})')
            except Exception as e:
                self.log('Open Redirect', 'ERROR', f'Error testing {uri}: {str(e)}')
    
    def test_jwt_structure(self, token: str):
        """Analyze JWT token structure and vulnerabilities"""
        print(f"\n{Fore.CYAN}=== Testing JWT Structure ==={Style.RESET_ALL}")
        
        try:
            # Decode without verification to inspect
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            print(f"\n{Fore.YELLOW}JWT Header:{Style.RESET_ALL}")
            print(json.dumps(header, indent=2))
            print(f"\n{Fore.YELLOW}JWT Payload:{Style.RESET_ALL}")
            print(json.dumps(payload, indent=2))
            
            # Check algorithm
            alg = header.get('alg', 'none')
            if alg in ['none', 'HS256']:
                self.log('JWT Algorithm', 'VULNERABLE', 
                       f'Weak algorithm detected: {alg}')
            else:
                self.log('JWT Algorithm', 'SECURE', 
                       f'Strong algorithm: {alg}')
            
            # Check expiration
            if 'exp' in payload:
                exp_time = datetime.fromtimestamp(payload['exp'])
                now = datetime.now()
                hours_valid = (exp_time - now).total_seconds() / 3600
                
                if hours_valid > 24:
                    self.log('Token Expiration', 'WARNING', 
                           f'Token valid for {hours_valid:.2f} hours')
                else:
                    self.log('Token Expiration', 'SECURE', 
                           f'Token expires in {hours_valid:.2f} hours')
            
            # Check for sensitive data in token
            sensitive_fields = ['password', 'ssn', 'credit_card', 'api_key']
            for field in sensitive_fields:
                if any(field in str(v).lower() for v in payload.values()):
                    self.log('Sensitive Data', 'VULNERABLE', 
                           f'Possible sensitive data in token: {field}')
            
        except Exception as e:
            self.log('JWT Structure', 'ERROR', f'Could not parse JWT: {str(e)}')
    
    def test_algorithm_confusion(self, token: str):
        """Test for algorithm confusion attack"""
        print(f"\n{Fore.CYAN}=== Testing Algorithm Confusion ==={Style.RESET_ALL}")
        
        try:
            # Decode original token
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            # Create malicious token with 'none' algorithm
            malicious_header = header.copy()
            malicious_header['alg'] = 'none'
            
            # Encode header and payload
            encoded_header = base64.urlsafe_b64encode(
                json.dumps(malicious_header).encode()
            ).decode().rstrip('=')
            
            encoded_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')
            
            malicious_token = f"{encoded_header}.{encoded_payload}."
            
            print(f"\n{Fore.YELLOW}Original Algorithm: {header.get('alg')}")
            print(f"Malicious Token (alg=none):{Style.RESET_ALL}")
            print(malicious_token[:100] + "...")
            
            self.log('Algorithm Confusion', 'INFO', 
                   'Generated malicious token with alg=none')
            
            return malicious_token
            
        except Exception as e:
            self.log('Algorithm Confusion', 'ERROR', f'Error: {str(e)}')
            return None
    
    def test_token_replay(self, token: str):
        """Test if token can be replayed"""
        print(f"\n{Fore.CYAN}=== Testing Token Replay ==={Style.RESET_ALL}")
        
        if not self.api_url:
            self.log('Token Replay', 'INFO', 
                   'No API URL provided, skipping replay test')
            return
        
        headers = {
            'Authorization': f'Bearer {token}',
            'User-Agent': 'Auth0-Security-Tester',
            'Content-Type': 'application/json'
        }
        
        try:
            # First request
            response1 = self.session.get(self.api_url, headers=headers, timeout=10)
            time.sleep(2)
            
            # Second request (replay)
            response2 = self.session.get(self.api_url, headers=headers, timeout=10)
            
            if response1.status_code == 200 and response2.status_code == 200:
                self.log('Token Replay', 'VULNERABLE', 
                       'Token can be replayed successfully')
            else:
                self.log('Token Replay', 'SECURE', 
                       'Token replay appears to be prevented')
                
        except Exception as e:
            self.log('Token Replay', 'ERROR', f'Error testing replay: {str(e)}')
    
    def test_cors_configuration(self):
        """Test CORS configuration"""
        print(f"\n{Fore.CYAN}=== Testing CORS Configuration ==={Style.RESET_ALL}")
        
        malicious_origins = [
            'https://evil.com',
            'http://localhost',
            'null'
        ]
        
        userinfo_url = f'https://{self.domain}/userinfo'
        
        for origin in malicious_origins:
            try:
                headers = {
                    'Origin': origin,
                    'Access-Control-Request-Method': 'GET',
                    'Access-Control-Request-Headers': 'authorization'
                }
                
                response = self.session.options(userinfo_url, headers=headers, timeout=10)
                
                allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
                
                if allow_origin == '*':
                    self.log('CORS', 'VULNERABLE', 
                           f'Wildcard CORS origin allowed')
                    break
                elif origin in allow_origin:
                    self.log('CORS', 'VULNERABLE', 
                           f'Malicious origin {origin} is allowed')
                else:
                    self.log('CORS', 'SECURE', 
                           f'Origin {origin} is blocked')
                    
            except Exception as e:
                self.log('CORS', 'ERROR', f'Error testing CORS: {str(e)}')
    
    def test_authorization_code_interception(self):
        """Test authorization code interception"""
        print(f"\n{Fore.CYAN}=== Testing Authorization Code Interception ==={Style.RESET_ALL}")
        
        # Generate auth URL without PKCE
        auth_url = f"https://{self.domain}/authorize?" + urllib.parse.urlencode({
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': 'openid profile email'
        })
        
        print(f"\n{Fore.YELLOW}Authorization URL (without PKCE):{Style.RESET_ALL}")
        print(auth_url)
        
        self.log('Authorization Code', 'INFO', 
               'Check if PKCE is enforced by manually testing the auth flow')
    
    def test_csrf_on_endpoints(self):
        """Test CSRF vulnerabilities"""
        print(f"\n{Fore.CYAN}=== Testing CSRF Vulnerabilities ==={Style.RESET_ALL}")
        
        if not self.target_url:
            self.log('CSRF', 'INFO', 'No target URL provided, skipping CSRF test')
            return
        
        # Test logout endpoint
        logout_endpoints = [
            f'{self.target_url}/logout',
            f'{self.target_url}/api/logout',
            f'https://{self.domain}/v2/logout'
        ]
        
        for endpoint in logout_endpoints:
            try:
                # Test without CSRF token
                response = self.session.get(endpoint, timeout=10)
                
                if response.status_code in [200, 302]:
                    self.log('CSRF', 'VULNERABLE', 
                           f'Logout endpoint {endpoint} has no CSRF protection')
                else:
                    self.log('CSRF', 'SECURE', 
                           f'Logout endpoint {endpoint} appears protected')
                    
            except Exception as e:
                self.log('CSRF', 'ERROR', f'Error testing {endpoint}: {str(e)}')
    
    def test_session_fixation(self):
        """Test session fixation vulnerability"""
        print(f"\n{Fore.CYAN}=== Testing Session Fixation ==={Style.RESET_ALL}")
        
        if not self.target_url:
            self.log('Session Fixation', 'INFO', 
                   'No target URL provided, skipping session fixation test')
            return
        
        try:
            # Get initial session
            response1 = self.session.get(self.target_url, timeout=10)
            cookies_before = self.session.cookies.get_dict()
            
            # Simulate login (this would need actual login flow)
            # For now, just check if session ID changes
            
            self.log('Session Fixation', 'INFO', 
                   'Manual testing required: Check if session ID changes after login')
            print(f"{Fore.YELLOW}Cookies before auth:{Style.RESET_ALL}", cookies_before)
            
        except Exception as e:
            self.log('Session Fixation', 'ERROR', f'Error: {str(e)}')
    
    def test_rate_limiting(self):
        """Test rate limiting on auth endpoints"""
        print(f"\n{Fore.CYAN}=== Testing Rate Limiting ==={Style.RESET_ALL}")
        
        token_url = f'https://{self.domain}/oauth/token'
        
        # Send multiple requests
        success_count = 0
        for i in range(20):
            try:
                data = {
                    'grant_type': 'authorization_code',
                    'client_id': self.client_id,
                    'code': 'invalid_code',
                    'redirect_uri': self.redirect_uri
                }
                
                response = self.session.post(token_url, data=data, timeout=5)
                
                if response.status_code != 429:
                    success_count += 1
                    
            except Exception:
                pass
        
        if success_count >= 15:
            self.log('Rate Limiting', 'VULNERABLE', 
                   f'{success_count}/20 requests succeeded - no rate limiting')
        else:
            self.log('Rate Limiting', 'SECURE', 
                   f'Rate limiting appears active ({success_count}/20 succeeded)')
    
    def generate_xss_payloads(self):
        """Generate XSS test payloads"""
        print(f"\n{Fore.CYAN}=== XSS Test Payloads ==={Style.RESET_ALL}")
        
        payloads = [
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(String.fromCharCode(88,83,83))</script>',
            '<svg/onload=alert(1)>',
            'javascript:alert(1)',
            '<iframe src="javascript:alert(1)">',
            '<body onload=alert(1)>'
        ]
        
        print(f"\n{Fore.YELLOW}Test these payloads in input fields:{Style.RESET_ALL}")
        for i, payload in enumerate(payloads, 1):
            print(f"{i}. {payload}")
        
        self.log('XSS Payloads', 'INFO', f'Generated {len(payloads)} XSS payloads for testing')
    
    def test_pkce_enforcement(self):
        """Test if PKCE is properly enforced"""
        print(f"\n{Fore.CYAN}=== Testing PKCE Enforcement ==={Style.RESET_ALL}")
        
        # Try auth without PKCE parameters
        auth_url_no_pkce = f"https://{self.domain}/authorize?" + urllib.parse.urlencode({
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': 'openid profile email'
        })
        
        print(f"\n{Fore.YELLOW}Test URL without PKCE:{Style.RESET_ALL}")
        print(auth_url_no_pkce)
        
        self.log('PKCE Enforcement', 'INFO', 
               'Manually verify if authorization fails without PKCE parameters')
    
    def generate_report(self):
        """Generate comprehensive security report"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print("SECURITY TEST REPORT")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"Test completed at: {datetime.now().isoformat()}")
        print(f"Target Domain: {self.domain}")
        print(f"Client ID: {self.client_id}\n")
        
        vulnerable = [r for r in self.results if r['status'] == 'VULNERABLE']
        warnings = [r for r in self.results if r['status'] == 'WARNING']
        secure = [r for r in self.results if r['status'] == 'SECURE']
        
        print(f"{Fore.RED}Vulnerabilities: {len(vulnerable)}")
        print(f"{Fore.YELLOW}Warnings: {len(warnings)}")
        print(f"{Fore.GREEN}Secure: {len(secure)}{Style.RESET_ALL}\n")
        
        if vulnerable:
            print(f"{Fore.RED}⚠️  VULNERABILITIES FOUND:{Style.RESET_ALL}")
            for v in vulnerable:
                print(f"{Fore.RED}  - {v['test']}: {v['details']}{Style.RESET_ALL}")
        
        if warnings:
            print(f"\n{Fore.YELLOW}⚡ WARNINGS:{Style.RESET_ALL}")
            for w in warnings:
                print(f"{Fore.YELLOW}  - {w['test']}: {w['details']}{Style.RESET_ALL}")
        
        # Save to JSON file
        report_file = f"auth0_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n{Fore.GREEN}Full report saved to: {report_file}{Style.RESET_ALL}")
        
        return self.results
    
    def run_all_tests(self, token: str = None):
        """Run all security tests"""
        print(f"{Fore.CYAN}Starting Auth0 Security Tests...{Style.RESET_ALL}\n")
        
        # Tests that don't require token
        self.test_open_redirect()
        self.test_cors_configuration()
        self.test_authorization_code_interception()
        self.test_csrf_on_endpoints()
        self.test_session_fixation()
        self.test_rate_limiting()
        self.test_pkce_enforcement()
        self.generate_xss_payloads()
        
        # Tests that require token
        if token:
            self.test_jwt_structure(token)
            self.test_algorithm_confusion(token)
            self.test_token_replay(token)
        else:
            self.log('Token Tests', 'INFO', 
                   'No token provided, skipping token-based tests')
        
        return self.generate_report()


def main():
    parser = argparse.ArgumentParser(
        description='Auth0 React Security Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 auth0_test.py --domain your-domain.auth0.com --client-id YOUR_CLIENT_ID
  python3 auth0_test.py --config config.json --token YOUR_ACCESS_TOKEN
        """
    )
    
    parser.add_argument('--domain', help='Auth0 domain (e.g., your-domain.auth0.com)')
    parser.add_argument('--client-id', help='Auth0 client ID')
    parser.add_argument('--redirect-uri', default='http://localhost:3000', 
                       help='Redirect URI (default: http://localhost:3000)')
    parser.add_argument('--target-url', help='Target application URL')
    parser.add_argument('--api-url', help='API endpoint URL for testing')
    parser.add_argument('--token', help='Access token for testing')
    parser.add_argument('--config', help='JSON config file with settings')
    
    args = parser.parse_args()
    
    # Load config from file or command line
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)
    else:
        if not args.domain or not args.client_id:
            parser.error('--domain and --client-id are required (or use --config)')
        
        config = {
            'domain': args.domain,
            'client_id': args.client_id,
            'redirect_uri': args.redirect_uri,
            'target_url': args.target_url or '',
            'api_url': args.api_url or ''
        }
    
    # Create tester and run tests
    tester = Auth0SecurityTester(config)
    tester.run_all_tests(token=args.token)


if __name__ == '__main__':
    main()