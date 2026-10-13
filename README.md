pip install requests beautifulsoup4//环境准备
import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin

def parse_webpage(url):
    """
    基础网页解析脚本
    功能：获取网页并提取标题、链接、表单、输入框、注释、脚本中的可疑信息
    """
    try:
        # 1. 发送 GET 请求，设置常见浏览器 UA，避免被简单拦截
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36"
        }
        resp = requests.get(url, headers=headers, timeout=10)
        resp.encoding = resp.apparent_encoding  # 自动修正编码，防止中文乱码
        html = resp.text

        print(f"[+] 状态码: {resp.status_code}")
        print(f"[+] 页面大小: {len(html)} 字符")
        print(f"[+] 最终URL: {resp.url}")
        print("-" * 60)

        # 2. 用 BeautifulSoup 解析 HTML
        soup = BeautifulSoup(html, "html.parser")

        # 3. 提取页面标题
        title = soup.title.string.strip() if soup.title and soup.title.string else "无标题"
        print(f"[标题] {title}")

        # 4. 提取所有链接（包括 a 标签的 href 和 link 标签）
        print("\n[链接]")
        links = set()
        for a in soup.find_all("a", href=True):
            full_url = urljoin(url, a["href"])
            links.add(full_url)
            print(f"  {a.get_text(strip=True)[:30]:30} -> {full_url}")
        if not links:
            print("  未发现链接")

        # 5. 提取所有表单及输入字段（CTF 中常用来找隐藏参数）
        print("\n[表单]")
        forms = soup.find_all("form")
        if not forms:
            print("  未发现表单")
        for i, form in enumerate(forms, 1):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            print(f"  表单 {i}: method={method}, action={urljoin(url, action)}")
            # 提取输入字段
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "无name")
                value = inp.get("value", "")
                typ = inp.get("type", inp.name)
                print(f"    - {typ:10} name={name:15} value={value}")

        # 6. 提取 HTML 注释（经常藏 flag 或提示）
        print("\n[注释]")
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        if not comments:
            print("  未发现注释")
        for c in comments:
            c = c.strip()
            if c:
                print(f"  <!-- {c} -->")

        # 7. 提取所有 script 和 style 中的可疑内容（如 flag、token、路径）
        print("\n[脚本/样式中的可疑字符串]")
        suspicious_keywords = ["flag", "token", "secret", "key", "admin", "debug", "api"]
        found = False
        for tag in soup.find_all(["script", "style"]):
            content = tag.string if tag.string else ""
            for kw in suspicious_keywords:
                if kw.lower() in content.lower():
                    # 只打印包含关键词的那一行附近内容
                    lines = content.splitlines()
                    for line in lines:
                        if kw.lower() in line.lower():
                            print(f"  [{tag.name}] {line.strip()[:120]}")
                            found = True
        if not found:
            print("  未发现明显可疑字符串")

        # 8. 提取所有 meta 标签（有时藏着重定向或提示）
        print("\n[Meta 标签]")
        for meta in soup.find_all("meta"):
            attrs = {k: v for k, v in meta.attrs.items()}
            print(f"  {attrs}")

        # 9. 提取所有图片、脚本、CSS 的引用路径（用于目录扫描或找线索）
        print("\n[资源引用]")
        for tag, attr in [("img", "src"), ("script", "src"), ("link", "href")]:
            for item in soup.find_all(tag):
                src = item.get(attr)
                if src:
                    print(f"  {tag:6} -> {urljoin(url, src)}")

        print("\n[+] 解析完成")

    except requests.exceptions.RequestException as e:
        print(f"[-] 请求失败: {e}")
    except Exception as e:
        print(f"[-] 解析出错: {e}")


if __name__ == "__main__":
    # 替换成你要解析的网页地址，例如 CTF 题目地址
    target_url = "http://example.com"
    parse_webpage(target_url)
    
