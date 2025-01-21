import asyncio
import aiohttp
import csv
from bs4 import BeautifulSoup
from typing import List, Tuple, Set
import logging
from collections import deque
import time
from itertools import product
import string

class SubdomainScanner:
    
    def __init__(self, 
                 concurrent_requests: int = 50,
                 timeout: float = 1.0,
                 max_retries: int = 2,
                 chunk_size: int = 1000):
        
        self.concurrent_requests = concurrent_requests
        self.timeout = timeout
        self.max_retries = max_retries
        self.chunk_size = chunk_size
        self.seen_subdomains: Set[str] = set()
        self.rate_limiter = asyncio.Semaphore(concurrent_requests)
        self.session = None
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        
        self.chars = string.ascii_lowercase + string.digits
        
    async def __aenter__(self):
        
        connector = aiohttp.TCPConnector(limit_per_host=self.concurrent_requests)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        
        if self.session:
            await self.session.close()
            
    async def check_subdomain(self, subdomain: str, domain: str) -> Tuple[str, str]:
    
        full_domain = f"{subdomain}.{domain}"
        if full_domain in self.seen_subdomains:
            return None
            
        self.seen_subdomains.add(full_domain)
        url = f"http://{full_domain}"
        
        async with self.rate_limiter:
            for attempt in range(self.max_retries):
                try:
                    async with self.session.get(url) as response:
                        if response.status == 200:
                            content = await response.text()
                            soup = BeautifulSoup(content, "html.parser")
                            title = soup.title.string if soup.title else "No Title"
                            return (full_domain, title)
                except Exception as e:
                    if attempt == self.max_retries - 1:
                        self.logger.debug(f"检查域名失败 {url}: {str(e)}")
                    await asyncio.sleep(0.1 * (attempt + 1))
        
        return None

    def generate_subdomains(self, length: int) -> List[str]:
        """ 笛卡尔积 """
        return [''.join(p) for p in product(self.chars, repeat=length)]
        
    async def scan_subdomains_chunk(self, domain: str, subdomains: List[str]) -> List[Tuple[str, str]]:

        tasks = [self.check_subdomain(subdomain, domain) for subdomain in subdomains]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]
        
    async def scan_domain(self, domain: str, min_length: int = 1, max_length: int = 3) -> List[Tuple[str, str]]:
        """ 扫描子域名 """
        all_results = []
        start_time = time.time()
        
        for length in range(min_length, max_length + 1):
            self.logger.info(f"扫描 {domain} 长度为 {length} 的子域名")
            subdomains = self.generate_subdomains(length)
            
            for i in range(0, len(subdomains), self.chunk_size):
                chunk = subdomains[i:i + self.chunk_size]
                results = await self.scan_subdomains_chunk(domain, chunk)
                all_results.extend(results)
                
                progress = (i + len(chunk)) / len(subdomains) * 100
                elapsed = time.time() - start_time
                self.logger.info(f"进度: {progress:.1f}% - 已发现: {len(all_results)} - 用时: {elapsed:.1f}秒")
                
        return all_results

    async def process_domains_file(self, input_file: str, output_file: str):
        try:
            with open(input_file, 'r') as f:
                domains = [row[0] for row in csv.reader(f) if row]
                
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Subdomain', 'Title', 'Domain'])
                
                for domain in domains:
                    self.logger.info(f"开始扫描: {domain}")
                    results = await self.scan_domain(domain)
                    
                    for subdomain, title in results:
                        writer.writerow([subdomain, title, domain])
                        
                    self.logger.info(f" {domain} 完成，共 {len(results)} 个子域名")
                    
        except Exception as e:
            self.logger.error(f"ERROR! : {str(e)}")
            raise

async def main():
    input_file = 'domains.csv'
    output_file = 'subdomains_output.csv'
    
    async with SubdomainScanner(
        concurrent_requests=50,
        timeout=1.0, 
        max_retries=2,
        chunk_size=1000
    ) as scanner:
        await scanner.process_domains_file(input_file, output_file)

if __name__ == "__main__":
    asyncio.run(main())