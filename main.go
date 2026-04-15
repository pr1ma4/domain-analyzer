package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "regexp"
    "strings"
    "sync"
    "time"

    "github.com/likexian/whois"
    "golang.org/x/net/idna"
)

// Структуры данных
type AnalyzeResponse struct {
    Whois       WhoisInfo      `json:"whois"`
    WhoisError  string         `json:"whois_error,omitempty"`
    DNS         DNSResponse    `json:"dns"`
    Server      ServerInfo     `json:"server"`
    ServerError string         `json:"server_error,omitempty"`
}

type WhoisInfo struct {
    RawText         string   `json:"raw_text"`
    Domain          string   `json:"domain"`
    DomainPunycode  string   `json:"domain_punycode"`
    IsFree          bool     `json:"is_free"`
    Registrar       string   `json:"registrar"`
    RegistrarIANA   string   `json:"registrar_iana"`
    AbuseEmail      string   `json:"abuse_email"`
    AbusePhone      string   `json:"abuse_phone"`
    CreationDate    string   `json:"creation_date"`
    ExpirationDate  string   `json:"expiration_date"`
    FreeDate        string   `json:"free_date"`
    UpdatedDate     string   `json:"updated_date"`
    NameServers     []string `json:"name_servers"`
    Statuses        []string `json:"statuses"`
    Person          string   `json:"person"`
    AdminContact    string   `json:"admin_contact"`
    RegistrantName  string   `json:"registrant_name"`
    RegistrantOrg   string   `json:"registrant_org"`
}

type DNSResponse struct {
    NSServers   []string                     `json:"ns_servers"`
    Zones       []NSZoneInfo                 `json:"zones"`
    Checks      map[string][]DNSCheckResult  `json:"checks"`
}

type NSZoneInfo struct {
    Server     string   `json:"server"`
    Zone       string   `json:"zone"`
    ResolvesTo []string `json:"resolves_to"`
    Status     string   `json:"status"`
}

type DNSCheckResult struct {
    DNSServer    string   `json:"dns_server"`
    ServerName   string   `json:"server_name"`
    Country      string   `json:"country"`
    CountryFlag  string   `json:"country_flag"`
    Records      []string `json:"records"`
    Error        string   `json:"error,omitempty"`
    ResponseTime int64    `json:"response_time_ms"`
}

type ServerInfo struct {
    IP              string  `json:"ip"`
    Hostname        string  `json:"hostname"`
    Org             string  `json:"org"`
    Country         string  `json:"country"`
    City            string  `json:"city"`
    Region          string  `json:"region"`
    Postal          string  `json:"postal"`
    Lat             float64 `json:"lat"`
    Lon             float64 `json:"lon"`
    WebServer       string  `json:"web_server"`
    HttpStatus      int     `json:"http_status"`
    HttpStatusText  string  `json:"http_status_text"`
}

// DNS серверы для проверки
var dnsServers = []struct {
    IP          string
    Name        string
    Country     string
    CountryFlag string
    City        string
}{
    {"8.8.8.8", "Google DNS", "USA", "🇺🇸", "Mountain View"},
    {"8.8.4.4", "Google DNS", "USA", "🇺🇸", "Mountain View"},
    {"1.1.1.1", "Cloudflare", "USA", "🇺🇸", "San Francisco"},
    {"1.0.0.1", "Cloudflare", "USA", "🇺🇸", "San Francisco"},
    {"9.9.9.9", "Quad9", "USA", "🇺🇸", "Chicago"},
    {"208.67.222.222", "OpenDNS", "USA", "🇺🇸", "San Francisco"},
    {"208.67.220.220", "OpenDNS", "USA", "🇺🇸", "San Francisco"},
    {"80.80.80.80", "Freenom", "Netherlands", "🇳🇱", "Amsterdam"},
    {"80.80.81.81", "Freenom", "Netherlands", "🇳🇱", "Amsterdam"},
    {"77.88.8.8", "Yandex DNS", "Russia", "🇷🇺", "Moscow"},
    {"77.88.8.1", "Yandex DNS", "Russia", "🇷🇺", "Moscow"},
    {"114.114.114.114", "114DNS", "China", "🇨🇳", "Beijing"},
    {"114.114.115.115", "114DNS", "China", "🇨🇳", "Beijing"},
    {"119.29.29.29", "DNSPod", "China", "🇨🇳", "Shenzhen"},
    {"223.5.5.5", "Alibaba DNS", "China", "🇨🇳", "Hangzhou"},
    {"223.6.6.6", "Alibaba DNS", "China", "🇨🇳", "Hangzhou"},
    {"103.99.150.10", "Cloudflare APAC", "India", "🇮🇳", "Mumbai"},
    {"164.124.101.2", "LG DACOM", "South Korea", "🇰🇷", "Seoul"},
    {"61.8.0.113", "Liquid Telecom", "Australia", "🇦🇺", "Sydney"},
    {"5.11.11.11", "Liquid Telecom", "South Africa", "🇿🇦", "Johannesburg"},
}

func main() {
    http.HandleFunc("/", handleHome)
    http.HandleFunc("/api/analyze", handleAnalyze)
    http.HandleFunc("/api/checkhost", handleCheckHostAPI)  // НОВЫЙ API
    http.HandleFunc("/checkhost", handleCheckHostPage)     // НОВАЯ СТРАНИЦА

    port := ":8080"
    fmt.Printf("🚀 DNS Tracker запущен!\n")
    fmt.Printf("📍 Открой: http://localhost%s\n", port)
    fmt.Printf("📍 CheckHost: http://localhost%s/checkhost\n", port)
    fmt.Printf("Нажми Ctrl+C для остановки\n\n")

    if err := http.ListenAndServe(port, nil); err != nil {
        log.Fatal("Ошибка:", err)
    }
}

func handleHome(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "web/index.html")
}

// Страница checkhost
func handleCheckHostPage(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    
    html := `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CheckHost - Быстрая проверка сервера</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        :root {
            --bg-primary: #f0f2f5;
            --bg-secondary: #ffffff;
            --bg-card: #ffffff;
            --text-primary: #333333;
            --text-secondary: #666666;
            --text-muted: #555555;
            --border-color: #e0e0e0;
            --border-light: #f0f0f0;
            --shadow: 0 2px 10px rgba(0,0,0,0.1);
            --btn-bg: #0066cc;
            --btn-hover: #0052a3;
            --accent: #0066cc;
        }
        
        body.dark {
            --bg-primary: #0a0a0f;
            --bg-secondary: #0d1117;
            --bg-card: #161b22;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --border-color: #21262d;
            --border-light: #1a1f2a;
            --shadow: 0 2px 10px rgba(0,0,0,0.5);
            --btn-bg: #1f6feb;
            --btn-hover: #388bfd;
            --accent: #58a6ff;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: var(--bg-primary);
            min-height: 100vh;
            padding: 20px;
            transition: background 0.3s ease;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        h1 {
            color: var(--accent);
            font-size: 32px;
        }
        
        .theme-toggle {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 40px;
            padding: 8px 16px;
            cursor: pointer;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s ease;
            color: var(--text-primary);
        }
        
        .theme-toggle:hover {
            background: var(--border-light);
        }
        
        .sub {
            color: var(--text-secondary);
            margin-bottom: 25px;
        }
        
        .search-card {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 30px;
            box-shadow: var(--shadow);
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
        }
        
        .search-box {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        input {
            flex: 2;
            padding: 14px 20px;
            font-size: 16px;
            border: 2px solid var(--border-color);
            border-radius: 12px;
            font-family: monospace;
            background: var(--bg-secondary);
            color: var(--text-primary);
            transition: all 0.3s;
        }
        
        input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(88,166,255,0.1);
        }
        
        button {
            padding: 14px 28px;
            font-size: 16px;
            cursor: pointer;
            background: var(--btn-bg);
            color: white;
            border: none;
            border-radius: 12px;
            font-weight: bold;
            transition: all 0.2s;
        }
        
        button:hover {
            background: var(--btn-hover);
            transform: translateY(-1px);
        }
        
        .result-grid {
            display: grid;
            grid-template-columns: 1fr 400px;
            gap: 20px;
        }
        
        .info-card {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 24px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
        }
        
        .info-title {
            font-size: 18px;
            font-weight: bold;
            color: var(--accent);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-light);
        }
        
        .info-row {
            display: flex;
            padding: 12px 0;
            border-bottom: 1px solid var(--border-light);
        }
        
        .info-label {
            width: 120px;
            font-weight: 600;
            color: var(--text-muted);
        }
        
        .info-value {
            flex: 1;
            color: var(--text-primary);
            word-break: break-word;
        }
        
        .info-value code {
            background: var(--bg-secondary);
            padding: 4px 8px;
            border-radius: 6px;
            font-family: monospace;
            border: 1px solid var(--border-color);
        }
        
        .http-2xx { background: #e8f5e9; color: #4caf50; display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: 600; }
        .http-3xx { background: #e3f2fd; color: #2196f3; display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: 600; }
        .http-4xx { background: #fff3e0; color: #ff9800; display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: 600; }
        .http-5xx { background: #ffebee; color: #f44336; display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: 600; }
        
        body.dark .http-2xx { background: #1b5e20; color: #81c784; }
        body.dark .http-3xx { background: #0d47a1; color: #64b5f6; }
        body.dark .http-4xx { background: #e65100; color: #ffb74d; }
        body.dark .http-5xx { background: #b71c1c; color: #ef5350; }
        
        .map-card {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 24px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
        }
        
        .server-map {
            height: 300px;
            border-radius: 12px;
            margin-top: 15px;
            overflow: hidden;
            background: #1a1a2e;
        }
        
        .leaflet-control-attribution {
            display: none !important;
        }
        
        .flag-icon {
            display: inline-block;
            width: 20px;
            height: 15px;
            margin-right: 6px;
            vertical-align: middle;
            background-size: cover;
        }
        
        .loading {
            text-align: center;
            padding: 60px;
            background: var(--bg-card);
            border-radius: 16px;
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
        }
        
        .error {
            background: #ffebee;
            color: #c62828;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
        }
        
        body.dark .error {
            background: #3a1a1a;
            color: #f85149;
        }
        
        @media (max-width: 768px) {
            .result-grid {
                grid-template-columns: 1fr;
            }
            .info-row {
                flex-direction: column;
            }
            .info-label {
                width: 100%;
                margin-bottom: 5px;
            }
            h1 {
                font-size: 28px;
            }
            .search-box {
                flex-direction: column;
            }
            .header-row {
                flex-direction: column;
                gap: 15px;
                align-items: flex-start;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header-row">
            <h1>⚡ CheckHost</h1>
            <button class="theme-toggle" onclick="toggleTheme()">
                <span class="theme-icon">🌙</span>
                <span>Темная тема</span>
            </button>
        </div>
        <div class="sub">Быстрая проверка сервера: IP, геолокация, HTTP статус</div>
        
        <div class="search-card">
            <div class="search-box">
                <input type="text" id="domain" placeholder="Введите домен (например, google.com, yandex.ru)" value="google.com">
                <button onclick="checkHost()">Проверить</button>
            </div>
        </div>
        
        <div id="result">
            <div class="loading">✨ Введите домен и нажмите "Проверить"</div>
        </div>
    </div>
    
    <script>
        let currentMap = null;
        let currentDomain = '';
        
        function toggleTheme() {
            const body = document.body;
            const themeToggle = document.querySelector('.theme-toggle');
            const themeIcon = themeToggle.querySelector('.theme-icon');
            const themeText = themeToggle.querySelector('span:last-child');
            
            if (body.classList.contains('dark')) {
                body.classList.remove('dark');
                themeIcon.textContent = '🌙';
                themeText.textContent = 'Темная тема';
                localStorage.setItem('theme', 'light');
            } else {
                body.classList.add('dark');
                themeIcon.textContent = '☀️';
                themeText.textContent = 'Светлая тема';
                localStorage.setItem('theme', 'dark');
            }
        }
        
        function loadTheme() {
            const savedTheme = localStorage.getItem('theme');
            if (savedTheme === 'dark') {
                document.body.classList.add('dark');
                const themeToggle = document.querySelector('.theme-toggle');
                if (themeToggle) {
                    themeToggle.querySelector('.theme-icon').textContent = '☀️';
                    themeToggle.querySelector('span:last-child').textContent = 'Светлая тема';
                }
            }
        }
        
        function getCountryCode(countryName) {
            if (!countryName) return null;
            const map = {
                'Russia': 'ru', 'USA': 'us', 'United States': 'us',
                'United Kingdom': 'gb', 'Germany': 'de', 'France': 'fr',
                'Netherlands': 'nl', 'China': 'cn', 'India': 'in',
                'Australia': 'au', 'Brazil': 'br', 'Japan': 'jp',
                'Canada': 'ca', 'Italy': 'it', 'Spain': 'es',
                'South Korea': 'kr', 'Singapore': 'sg'
            };
            return map[countryName] || countryName.substring(0, 2).toLowerCase();
        }
        
        function getFlagHtml(countryName) {
            if (!countryName) return '';
            const code = getCountryCode(countryName);
            if (!code) return '';
            return '<span class=\"flag-icon\" style=\"background-image: url(https://flagcdn.com/20x15/' + code + '.png);\"></span>';
        }
        
        function getHttpStatusClass(status) {
            if (status >= 200 && status < 300) return 'http-2xx';
            if (status >= 300 && status < 400) return 'http-3xx';
            if (status >= 400 && status < 500) return 'http-4xx';
            if (status >= 500 && status < 600) return 'http-5xx';
            return '';
        }
        
        function initMap(lat, lon, city, country) {
            var mapContainer = document.getElementById('server-map');
            if (!mapContainer) return;
            
            if (currentMap) {
                currentMap.remove();
            }
            
            var latitude = lat || 20;
            var longitude = lon || 0;
            
            if (latitude === 0 && longitude === 0) {
                latitude = 20;
                longitude = 0;
            }
            
            var isDark = document.body.classList.contains('dark');
            var tileUrl = isDark ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png' : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png';
            
            currentMap = L.map('server-map').setView([latitude, longitude], 4);
            
            L.tileLayer(tileUrl, {
                attribution: '',
                subdomains: 'abcd',
                maxZoom: 19
            }).addTo(currentMap);
            
            var marker = L.marker([latitude, longitude]).addTo(currentMap);
            
            var popupText = '';
            if (city && country) popupText = city + ', ' + country;
            else if (country) popupText = country;
            else popupText = currentDomain;
            
            marker.bindPopup(popupText).openPopup();
        }
        
        async function checkHost() {
            var domain = document.getElementById('domain').value.trim();
            if (!domain) {
                alert('Введите домен');
                return;
            }
            
            currentDomain = domain;
            
            var resultDiv = document.getElementById('result');
            resultDiv.innerHTML = '<div class=\"loading\">⏳ Проверка сервера...</div>';
            
            try {
                var response = await fetch('/api/checkhost', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({domain: domain})
                });
                
                if (!response.ok) throw new Error('Ошибка сервера');
                
                var data = await response.json();
                renderResult(data, domain);
                
            } catch (error) {
                resultDiv.innerHTML = '<div class=\"error\">❌ ' + error.message + '</div>';
            }
        }
        
        function renderResult(data, domain) {
            var server = data.server;
            
            if (!server || !server.ip) {
                document.getElementById('result').innerHTML = '<div class=\"error\">Нет данных о сервере</div>';
                return;
            }
            
            var statusClass = getHttpStatusClass(server.http_status);
            var statusHtml = server.http_status ? 
                '<span class=\"' + statusClass + '\">' + server.http_status + ' ' + (server.http_status_text || '') + '</span>' : 
                '<span>—</span>';
            
            var flagHtml = getFlagHtml(server.country);
            
            var html = '<div class=\"result-grid\">';
            html += '<div class=\"info-card\">';
            html += '<div class=\"info-title\">📊 Информация о сервере</div>';
            html += '<div class=\"info-row\"><div class=\"info-label\">🌐 Domain:</div><div class=\"info-value\"><strong>' + escapeHtml(domain) + '</strong></div></div>';
            html += '<div class=\"info-row\"><div class=\"info-label\">🖥️ IP Address:</div><div class=\"info-value\"><code>' + escapeHtml(server.ip) + '</code></div></div>';
            html += '<div class=\"info-row\"><div class=\"info-label\">🏢 Hostname:</div><div class=\"info-value\">' + escapeHtml(server.hostname || '—') + '</div></div>';
            html += '<div class=\"info-row\"><div class=\"info-label\">📡 Organization:</div><div class=\"info-value\">' + escapeHtml(server.org || '—') + '</div></div>';
            html += '<div class=\"info-row\"><div class=\"info-label\">🌍 Location:</div><div class=\"info-value\">' + flagHtml + ' ' + escapeHtml(server.country || '—') + (server.city ? ', ' + escapeHtml(server.city) : '') + '</div></div>';
            html += '<div class=\"info-row\"><div class=\"info-label\">🌐 HTTP Status:</div><div class=\"info-value\">' + statusHtml + '</div></div>';
            html += '<div class=\"info-row\"><div class=\"info-label\">⚙️ Web Server:</div><div class=\"info-value\">' + escapeHtml(server.web_server || '—') + '</div></div>';
            html += '</div>';
            
            html += '<div class=\"map-card\">';
            html += '<div class=\"info-title\">🗺️ Геолокация сервера</div>';
            html += '<div id=\"server-map\" class=\"server-map\"></div>';
            html += '<div style=\"font-size: 12px; color: var(--text-muted); margin-top: 12px; text-align: center;\">';
            html += server.city && server.country ? flagHtml + ' ' + server.city + ', ' + server.country : (server.country ? flagHtml + ' ' + server.country : 'Расположение сервера');
            html += '</div></div></div>';
            
            document.getElementById('result').innerHTML = html;
            
            if (server.lat && server.lon) {
                setTimeout(function() {
                    initMap(server.lat, server.lon, server.city, server.country);
                }, 100);
            }
        }
        
        function escapeHtml(text) {
            if (!text) return '';
            return text.replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            });
        }
        
        loadTheme();
        
        document.getElementById('domain').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') checkHost();
        });
    </script>
</body>
</html>`
    
    fmt.Fprint(w, html)
}

// API для быстрой проверки хоста (без WHOIS и DNS)
func handleCheckHostAPI(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    var request struct {
        Domain string `json:"domain"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    domain := strings.TrimSpace(request.Domain)
    if domain == "" {
        http.Error(w, "Domain is required", http.StatusBadRequest)
        return
    }
    
    // Конвертируем кириллицу в punycode
    punycodeDomain := toPunycode(domain)
    
    // Получаем IP
    var serverIP string
    ips, err := net.LookupIP(punycodeDomain)
    if err == nil && len(ips) > 0 {
        for _, ip := range ips {
            if ipv4 := ip.To4(); ipv4 != nil {
                serverIP = ipv4.String()
                break
            }
        }
        if serverIP == "" {
            serverIP = ips[0].String()
        }
    }
    
    // Получаем информацию о сервере
    serverInfo := getServerInfo(serverIP, domain)
    
    response := struct {
        Server ServerInfo `json:"server"`
    }{
        Server: serverInfo,
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func toPunycode(domain string) string {
    if !strings.ContainsAny(domain, "абвгдеёжзийклмнопрстуфхцчшщъыьэюя") {
        return domain
    }
    punycode, err := idna.ToASCII(domain)
    if err != nil {
        return domain
    }
    return punycode
}

func getWhoisInfo(domain string) (*WhoisInfo, error) {
    result := &WhoisInfo{}
    result.Domain = domain

    punycodeDomain := toPunycode(domain)
    result.DomainPunycode = punycodeDomain

    var raw string
    var err error

    // ==================== ОБРАБОТКА .tj ДОМЕНОВ ====================
    if strings.HasSuffix(strings.ToLower(domain), ".tj") {
        raw, err = queryWhoisFromNukta(punycodeDomain)
        if err != nil {
            if strings.Contains(err.Error(), "domain is free") {
                result.IsFree = true
                result.Registrar = "—"
                result.CreationDate = "—"
                result.ExpirationDate = "—"
                result.NameServers = []string{}
                result.Statuses = []string{"FREE"}
                result.RawText = "Домен свободен"
                return result, nil
            }
            return nil, fmt.Errorf("ошибка получения WHOIS для .tj домена: %v", err)
        }
        
        result.RawText = raw
        result.IsFree = false
        
        lines := strings.Split(raw, "\n")
        for _, line := range lines {
            lineLower := strings.ToLower(line)
            
            if strings.Contains(lineLower, "registered:") {
                parts := strings.SplitN(line, ":", 2)
                if len(parts) == 2 {
                    dateStr := strings.TrimSpace(parts[1])
                    result.CreationDate = convertRussianDateToISO(dateStr)
                }
            }
            
            if strings.Contains(lineLower, "name server:") {
                parts := strings.SplitN(line, ":", 2)
                if len(parts) == 2 {
                    ns := strings.TrimSpace(strings.ToLower(parts[1]))
                    ns = strings.TrimSuffix(ns, ".")
                    if ns != "" {
                        result.NameServers = append(result.NameServers, ns)
                    }
                }
            }
            
            if strings.Contains(lineLower, "registrar:") {
                parts := strings.SplitN(line, ":", 2)
                if len(parts) == 2 {
                    result.Registrar = strings.TrimSpace(parts[1])
                }
            }
        }
        
        if result.Registrar == "" && strings.Contains(raw, "Tajiktelecom") {
            result.Registrar = "Tajiktelecom"
        }
        
        if result.CreationDate == "" {
            dateRegex := regexp.MustCompile(`(\d{1,2})\s+(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+(\d{4})`)
            if match := dateRegex.FindStringSubmatch(raw); len(match) > 3 {
                dateStr := fmt.Sprintf("%s %s %s", match[1], match[2], match[3])
                result.CreationDate = convertRussianDateToISO(dateStr)
            }
        }
        
        if result.ExpirationDate == "" {
            result.ExpirationDate = "не указана"
        }
        
        result.Statuses = append(result.Statuses, "REGISTERED")
        return result, nil
    }
    // ==================== КОНЕЦ .tj ====================

    // ==================== ОБРАБОТКА .vip ДОМЕНОВ ====================
    if strings.HasSuffix(strings.ToLower(domain), ".vip") {
        raw, err = queryWhoisServerWithTimeout("whois.nic.vip:43", punycodeDomain, 5*time.Second)
        if err != nil {
            raw, err = queryWhoisServerWithTimeout("whois.verisign-grs.com:43", punycodeDomain, 5*time.Second)
            if err != nil {
                return nil, fmt.Errorf("WHOIS сервер .vip не ответил: %v", err)
            }
        }
        
        result.RawText = raw
        rawLower := strings.ToLower(raw)
        
        hasCreationDate := strings.Contains(rawLower, "creation date:")
        hasRegistryExpiry := strings.Contains(rawLower, "registry expiry date:")
        hasNameServers := strings.Contains(rawLower, "name server:") || strings.Contains(rawLower, "nserver:")
        hasRegistrar := strings.Contains(rawLower, "registrar:")
        
        if hasCreationDate || hasRegistryExpiry || hasNameServers || hasRegistrar {
            result.IsFree = false
        } else {
            freeKeywords := []string{
                "no match", "not found", "status: free", "is free", "available",
                "no data found", "domain not found", "no entries found",
            }
            isFree := false
            for _, keyword := range freeKeywords {
                if strings.Contains(rawLower, keyword) {
                    isFree = true
                    break
                }
            }
            result.IsFree = isFree
        }
        
        if result.IsFree {
            result.Registrar = "—"
            result.CreationDate = "—"
            result.ExpirationDate = "—"
            result.NameServers = []string{}
            result.Statuses = []string{"FREE"}
            return result, nil
        }
        
        extractValue := func(pattern string) string {
            re := regexp.MustCompile(`(?i)` + pattern + `:\s*(.+)$`)
            lines := strings.Split(raw, "\n")
            for _, line := range lines {
                if matches := re.FindStringSubmatch(line); len(matches) > 1 {
                    val := strings.TrimSpace(matches[1])
                    val = strings.TrimSuffix(val, ".")
                    if val != "" && !strings.HasPrefix(val, "http") {
                        return val
                    }
                }
            }
            return ""
        }
        
        extractDate := func(pattern string) string {
            re := regexp.MustCompile(`(?i)` + pattern + `:\s*(\d{4}-\d{2}-\d{2})`)
            lines := strings.Split(raw, "\n")
            for _, line := range lines {
                if matches := re.FindStringSubmatch(line); len(matches) > 1 {
                    return matches[1]
                }
            }
            return ""
        }
        
        result.Registrar = extractValue("registrar")
        if result.Registrar == "" {
            result.Registrar = extractValue("Registrar")
        }
        
        result.CreationDate = extractDate("Creation Date")
        result.ExpirationDate = extractDate("Registry Expiry Date")
        result.UpdatedDate = extractDate("Updated Date")
        
        nsRegex := regexp.MustCompile(`(?i)(?:Name Server|nserver):\s*(\S+)`)
        matches := nsRegex.FindAllStringSubmatch(raw, -1)
        nsMap := make(map[string]bool)
        for _, m := range matches {
            if len(m) > 1 {
                ns := strings.ToLower(strings.TrimSuffix(m[1], "."))
                nsMap[ns] = true
            }
        }
        for ns := range nsMap {
            result.NameServers = append(result.NameServers, ns)
        }
        
        statusRegex := regexp.MustCompile(`(?i)(?:Domain Status):\s*([a-zA-Z]+)`)
        statusMatches := statusRegex.FindAllStringSubmatch(raw, -1)
        for _, m := range statusMatches {
            if len(m) > 1 {
                result.Statuses = append(result.Statuses, strings.ToUpper(m[1]))
            }
        }
        
        return result, nil
    }
    // ==================== КОНЕЦ .vip ====================

    // ==================== ОБРАБОТКА .ru ПОДДОМЕНОВ ====================
    isRuSubdomain := strings.HasSuffix(strings.ToLower(domain), ".com.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".net.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".org.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".pp.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".msk.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".spb.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".nov.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".kuban.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".vlg.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".nsk.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".ekb.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".kras.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".perm.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".surgut.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".tyumen.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".chel.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".samara.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".ufa.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".kazan.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".omsk.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".saratov.ru") ||
                     strings.HasSuffix(strings.ToLower(domain), ".yaroslavl.ru")

    if isRuSubdomain {
        raw, err = queryWhoisServerWithTimeout("whois.nic.ru:43", punycodeDomain, 5*time.Second)
        if err != nil {
            raw, err = whois.Whois(punycodeDomain)
        }
        
        result.RawText = raw
        rawLower := strings.ToLower(raw)
        
        hasDomainName := strings.Contains(rawLower, "domain name:") && strings.Contains(rawLower, strings.ToLower(domain))
        hasRegistryDomainId := strings.Contains(rawLower, "registry domain id:")
        hasCreationDate := strings.Contains(rawLower, "creation date:")
        hasNameServers := strings.Contains(rawLower, "nserver:") || strings.Contains(rawLower, "name server:")
        hasState := strings.Contains(rawLower, "state:") && !strings.Contains(rawLower, "state: free")
        hasRegistrar := strings.Contains(rawLower, "registrar:")
        
        if hasDomainName || hasRegistryDomainId || hasCreationDate || hasNameServers || hasState || hasRegistrar {
            result.IsFree = false
        } else if strings.Contains(rawLower, "no entries found") || strings.Contains(rawLower, "not found") {
            result.IsFree = true
        } else {
            result.IsFree = len(raw) < 100
        }
        
        if result.IsFree {
            result.Registrar = "—"
            result.CreationDate = "—"
            result.ExpirationDate = "—"
            result.NameServers = []string{}
            result.Statuses = []string{"FREE"}
            return result, nil
        }
        
        extractValue := func(pattern string) string {
            re := regexp.MustCompile(`(?i)` + pattern + `:\s*(.+)$`)
            lines := strings.Split(raw, "\n")
            for _, line := range lines {
                if matches := re.FindStringSubmatch(line); len(matches) > 1 {
                    val := strings.TrimSpace(matches[1])
                    val = strings.TrimSuffix(val, ".")
                    if val != "" && !strings.HasPrefix(val, "http") {
                        return val
                    }
                }
            }
            return ""
        }
        
        extractDate := func(pattern string) string {
            re := regexp.MustCompile(`(?i)` + pattern + `:\s*(\d{4}-\d{2}-\d{2})`)
            lines := strings.Split(raw, "\n")
            for _, line := range lines {
                if matches := re.FindStringSubmatch(line); len(matches) > 1 {
                    return matches[1]
                }
            }
            return ""
        }
        
        result.Registrar = extractValue("registrar")
        result.CreationDate = extractDate("creation date")
        result.ExpirationDate = extractDate("paid-till")
        
        nsRegex := regexp.MustCompile(`(?i)nserver:\s*(\S+)`)
        matches := nsRegex.FindAllStringSubmatch(raw, -1)
        for _, m := range matches {
            if len(m) > 1 {
                ns := strings.ToLower(strings.TrimSuffix(m[1], "."))
                result.NameServers = append(result.NameServers, ns)
            }
        }
        
        stateRegex := regexp.MustCompile(`(?i)state:\s*(.+)`)
        if match := stateRegex.FindStringSubmatch(raw); len(match) > 1 {
            result.Statuses = append(result.Statuses, strings.ToUpper(match[1]))
        }
        
        return result, nil
    }
    // ==================== КОНЕЦ .ru ПОДДОМЕНОВ ====================

    // ==================== ОСНОВНОЙ WHOIS ЗАПРОС ====================
    raw, err = whois.Whois(punycodeDomain)
    if err != nil {
        raw, err = whois.Whois(domain)
        if err != nil {
            return nil, err
        }
    }
    
    result.RawText = raw
    rawLower := strings.ToLower(raw)
    
    // Признаки зарегистрированного домена
    hasCreationDate := strings.Contains(rawLower, "creation date:") && !strings.Contains(rawLower, "creation date: 0000")
    hasRegistrar := strings.Contains(rawLower, "registrar:") && !strings.Contains(rawLower, "registrar: none")
    hasNameServers := strings.Contains(rawLower, "name server:") || strings.Contains(rawLower, "nserver:")
    hasExpiryDate := strings.Contains(rawLower, "registry expiry date:") || strings.Contains(rawLower, "expiry date:")
    hasDomainStatus := strings.Contains(rawLower, "domain status:") && !strings.Contains(rawLower, "status: free")
    hasRegistryDomainId := strings.Contains(rawLower, "registry domain id:")
    hasUpdatedDate := strings.Contains(rawLower, "updated date:")
    hasDNSSEC := strings.Contains(rawLower, "dnssec:")
    
    // Если есть признаки регистрации - домен НЕ свободен
    if hasCreationDate || hasRegistrar || hasNameServers || hasExpiryDate || hasDomainStatus || hasRegistryDomainId || hasUpdatedDate || hasDNSSEC {
        result.IsFree = false
    } else {
        freeKeywords := []string{
            "no match", "not found", "status: free", "is free", "available",
            "no data found", "domain not found", "no entries found",
            "not registered", "is available for registration", "no object found",
            "no matching records", "not been registered",
        }
        isFree := false
        for _, keyword := range freeKeywords {
            if strings.Contains(rawLower, keyword) {
                isFree = true
                break
            }
        }
        result.IsFree = isFree
    }
    
    // Дополнительная проверка: если есть Domain Name и Creation Date - точно не свободен
    if strings.Contains(rawLower, "domain name:") && (hasCreationDate || hasRegistryDomainId) {
        result.IsFree = false
    }
    
    if result.IsFree {
        result.Registrar = "—"
        result.CreationDate = "—"
        result.ExpirationDate = "—"
        result.NameServers = []string{}
        result.Statuses = []string{"FREE"}
        return result, nil
    }
    
    // Парсинг данных для зарегистрированного домена
    extractValue := func(pattern string) string {
        re := regexp.MustCompile(`(?i)` + pattern + `:\s*(.+)$`)
        lines := strings.Split(raw, "\n")
        for _, line := range lines {
            if matches := re.FindStringSubmatch(line); len(matches) > 1 {
                val := strings.TrimSpace(matches[1])
                val = strings.TrimSuffix(val, ".")
                if val != "" && !strings.HasPrefix(val, "http") {
                    return val
                }
            }
        }
        return ""
    }
    
    extractDate := func(pattern string) string {
        re := regexp.MustCompile(`(?i)` + pattern + `:\s*(\d{4}-\d{2}-\d{2})`)
        lines := strings.Split(raw, "\n")
        for _, line := range lines {
            if matches := re.FindStringSubmatch(line); len(matches) > 1 {
                return matches[1]
            }
        }
        return ""
    }
    
    result.Registrar = extractValue("registrar")
    if result.Registrar == "" {
        result.Registrar = extractValue("Registrar")
    }
    
    result.CreationDate = extractDate("Creation Date")
    if result.CreationDate == "" {
        result.CreationDate = extractDate("created")
    }
    if result.CreationDate == "" {
        result.CreationDate = extractDate("Registered On")
    }
    
    result.ExpirationDate = extractDate("Registry Expiry Date")
    if result.ExpirationDate == "" {
        result.ExpirationDate = extractDate("Expiry Date")
    }
    if result.ExpirationDate == "" {
        result.ExpirationDate = extractDate("paid-till")
    }
    
    result.UpdatedDate = extractDate("Updated Date")
    if result.UpdatedDate == "" {
        result.UpdatedDate = extractDate("Last updated on")
    }
    
    result.FreeDate = extractDate("free-date")
    
    // Name Servers
    nsRegex := regexp.MustCompile(`(?i)(?:Name Server|nserver):\s*(\S+)`)
    matches := nsRegex.FindAllStringSubmatch(raw, -1)
    nsMap := make(map[string]bool)
    for _, m := range matches {
        if len(m) > 1 {
            ns := strings.ToLower(strings.TrimSuffix(m[1], "."))
            nsMap[ns] = true
        }
    }
    for ns := range nsMap {
        result.NameServers = append(result.NameServers, ns)
    }
    
    // Statuses
    statusRegex := regexp.MustCompile(`(?i)(?:Domain Status|state):\s*(.+)$`)
    lines := strings.Split(raw, "\n")
    for _, line := range lines {
        if matches := statusRegex.FindStringSubmatch(line); len(matches) > 1 {
            statusStr := matches[1]
            parts := strings.FieldsFunc(statusStr, func(r rune) bool {
                return r == ' ' || r == ','
            })
            for _, p := range parts {
                p = strings.TrimSpace(p)
                if p != "" && !strings.Contains(p, "https://") {
                    result.Statuses = append(result.Statuses, strings.ToUpper(p))
                }
            }
        }
    }
    
    result.Person = extractValue("person")
    if result.Person == "" {
        result.Person = extractValue("Registrant Name")
    }
    result.RegistrantName = result.Person
    
    result.RegistrantOrg = extractValue("org")
    if result.RegistrantOrg == "" {
        result.RegistrantOrg = extractValue("Registrant Organization")
    }
    
    result.AdminContact = extractValue("admin-contact")
    if result.AdminContact == "" {
        result.AdminContact = extractValue("Admin Email")
    }
    
    return result, nil
}
// Вспомогательная функция min
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func queryWhoisServer(server string, query string) (string, error) {
    return queryWhoisServerWithTimeout(server, query, 10*time.Second)
}

// Функция для WHOIS запроса с таймаутом
func queryWhoisServerWithTimeout(server string, query string, timeout time.Duration) (string, error) {
    conn, err := net.DialTimeout("tcp", server, timeout)
    if err != nil {
        return "", err
    }
    defer conn.Close()
    
    conn.SetReadDeadline(time.Now().Add(timeout))
    
    fmt.Fprintf(conn, "%s\r\n", query)
    
    var response strings.Builder
    buf := make([]byte, 4096)
    for {
        n, err := conn.Read(buf)
        if n > 0 {
            response.Write(buf[:n])
        }
        if err != nil {
            break
        }
    }
    
    return response.String(), nil
}

func convertRussianDateToISO(dateStr string) string {
    months := map[string]string{
        "января": "01", "февраля": "02", "марта": "03", "апреля": "04",
        "мая": "05", "июня": "06", "июля": "07", "августа": "08",
        "сентября": "09", "октября": "10", "ноября": "11", "декабря": "12",
    }
    
    parts := strings.Split(dateStr, " ")
    if len(parts) >= 3 {
        day := parts[0]
        month := months[strings.ToLower(parts[1])]
        year := parts[2]
        if month != "" {
            if len(day) == 1 {
                day = "0" + day
            }
            return fmt.Sprintf("%s-%s-%s", year, month, day)
        }
    }
    return dateStr
}


func stripTags(s string) string {
    re := regexp.MustCompile(`<[^>]*>`)
    cleaned := re.ReplaceAllString(s, "")
    cleaned = strings.TrimSpace(cleaned)
    spaceRegex := regexp.MustCompile(`\s+`)
    cleaned = spaceRegex.ReplaceAllString(cleaned, " ")
    return cleaned
}


// Функция для парсинга WHOIS с nukta.tj
func queryWhoisFromNukta(domain string) (string, error) {
    client := http.Client{Timeout: 10 * time.Second}
    url := fmt.Sprintf("https://nukta.tj/%s", domain)
    
    resp, err := client.Get(url)
    if err != nil {
        return "", fmt.Errorf("ошибка запроса к nukta.tj: %v", err)
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("ошибка чтения ответа: %v", err)
    }
    
    html := string(body)
    
    // Проверяем, зарегистрирован ли домен
    if strings.Contains(html, "зарегистрирован") {
        var result strings.Builder
        
        // Извлекаем основную информацию из параграфа
        infoRegex := regexp.MustCompile(`<div class="information">.*?<p>(.*?)</p>`)
        if match := infoRegex.FindStringSubmatch(html); len(match) > 1 {
            infoText := stripTags(match[1])
            result.WriteString("Information: " + infoText + "\n")
            
            // Пробуем извлечь дату истечения (если есть)
            expiryRegex := regexp.MustCompile(`(?:оплачен до|expires|paid till)[:\s]*(\d{1,2}\s+\w+\s+\d{4})`)
            if match := expiryRegex.FindStringSubmatch(infoText); len(match) > 1 {
                result.WriteString(fmt.Sprintf("Expires: %s\n", match[1]))
            }
        }
        
        // Извлекаем регистратора
        if strings.Contains(html, "Tajiktelecom") {
            result.WriteString("Registrar: Tajiktelecom\n")
        }
        
        // Извлекаем NS серверы
        nsRegex := regexp.MustCompile(`<strong>([a-zA-Z0-9\-]+\.cloudflare\.com)</strong>`)
        nsMatches := nsRegex.FindAllStringSubmatch(html, -1)
        for _, nsMatch := range nsMatches {
            if len(nsMatch) > 1 {
                result.WriteString(fmt.Sprintf("Name Server: %s\n", nsMatch[1]))
            }
        }
        
        // Извлекаем дату регистрации
        dateRegex := regexp.MustCompile(`(\d{1,2})\s+(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+(\d{4})`)
        if match := dateRegex.FindStringSubmatch(html); len(match) > 3 {
            result.WriteString(fmt.Sprintf("Registered: %s %s %s\n", match[1], match[2], match[3]))
        }
        
        // Извлекаем владельца
        ownerRegex := regexp.MustCompile(`владельцем домена является\s+<strong>([^<]+)</strong>`)
        if match := ownerRegex.FindStringSubmatch(html); len(match) > 1 {
            result.WriteString(fmt.Sprintf("Owner: %s\n", match[1]))
        }
        
        if result.Len() == 0 {
            return "", fmt.Errorf("не удалось извлечь WHOIS информацию")
        }
        
        return result.String(), nil
    } else if strings.Contains(html, "свободен") || strings.Contains(html, "не зарегистрирован") {
        return "", fmt.Errorf("domain is free")
    }
    
    return "", fmt.Errorf("unknown status")
}


func getNSServers(domain string) ([]string, error) {
    resolver := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            d := net.Dialer{Timeout: 5 * time.Second}
            return d.DialContext(ctx, "udp", "8.8.8.8:53")
        },
    }

    nsRecords, err := resolver.LookupNS(context.Background(), domain)
    if err != nil {
        return nil, err
    }

    var nsServers []string
    for _, ns := range nsRecords {
        nsServers = append(nsServers, strings.TrimSuffix(strings.ToLower(ns.Host), "."))
    }

    return nsServers, nil
}

func checkDNSOnServer(domain string, recordType string, dnsIP string) ([]string, int64, error) {
    start := time.Now()

    resolver := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            d := net.Dialer{Timeout: 5 * time.Second}
            return d.DialContext(ctx, "udp", dnsIP+":53")
        },
    }

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    var records []string
    var err error

    switch recordType {
    case "A":
        ips, err := resolver.LookupIP(ctx, "ip4", domain)
        if err == nil {
            for _, ip := range ips {
                records = append(records, ip.String())
            }
        }

    case "AAAA":
        ips, err := resolver.LookupIP(ctx, "ip6", domain)
        if err == nil {
            for _, ip := range ips {
                records = append(records, ip.String())
            }
        } else if strings.Contains(err.Error(), "no such host") {
            err = nil
            records = []string{}
        }

    case "MX":
        mxRecords, err := resolver.LookupMX(ctx, domain)
        if err == nil {
            for _, mx := range mxRecords {
                records = append(records, fmt.Sprintf("%s (priority %d)", strings.TrimSuffix(mx.Host, "."), mx.Pref))
            }
        }

    case "TXT":
        txtRecords, err := resolver.LookupTXT(ctx, domain)
        if err == nil {
            records = txtRecords
        }

    case "NS":
        nsRecords, err := resolver.LookupNS(ctx, domain)
        if err == nil {
            for _, ns := range nsRecords {
                records = append(records, strings.TrimSuffix(strings.ToLower(ns.Host), "."))
            }
        } else {
            err = nil
            records = []string{}
        }

    case "CNAME":
        cname, err := resolver.LookupCNAME(ctx, domain)
        if err == nil {
            records = []string{strings.TrimSuffix(cname, ".")}
        }
    }

    elapsed := time.Since(start).Milliseconds()

    if err != nil {
        return nil, elapsed, err
    }

    return records, elapsed, nil
}

func checkNSZones(domain string, nsServers []string) []NSZoneInfo {
    var zones []NSZoneInfo
    var mu sync.Mutex
    var wg sync.WaitGroup

    for _, ns := range nsServers {
        wg.Add(1)
        go func(nameServer string) {
            defer wg.Done()

            ips, err := net.LookupIP(nameServer)
            if err != nil {
                mu.Lock()
                zones = append(zones, NSZoneInfo{
                    Server: nameServer,
                    Status: "❌ Не резолвится",
                })
                mu.Unlock()
                return
            }

            var ipStrings []string
            for _, ip := range ips {
                if ipv4 := ip.To4(); ipv4 != nil {
                    ipStrings = append(ipStrings, ipv4.String())
                }
            }

            status := "✅ Активен"
            if len(ipStrings) == 0 {
                status = "⚠️ Нет IPv4"
            }

            mu.Lock()
            zones = append(zones, NSZoneInfo{
                Server:     nameServer,
                Zone:       domain,
                ResolvesTo: ipStrings,
                Status:     status,
            })
            mu.Unlock()
        }(ns)
    }

    wg.Wait()
    return zones
}

func getServerInfo(ip string, domain string) ServerInfo {
    info := ServerInfo{IP: ip}

    if ip == "" || ip == "0.0.0.0" {
        return info
    }

    // Получаем геоданные
    client := http.Client{Timeout: 5 * time.Second}
    resp, err := client.Get("https://ipinfo.io/" + ip + "/json")
    if err == nil {
        defer resp.Body.Close()

        var data struct {
            Hostname string `json:"hostname"`
            Org      string `json:"org"`
            Country  string `json:"country"`
            Region   string `json:"region"`
            City     string `json:"city"`
            Postal   string `json:"postal"`
            Loc      string `json:"loc"`
        }

        if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
            info.Hostname = data.Hostname
            info.Org = data.Org
            info.Country = data.Country
            info.Region = data.Region
            info.City = data.City
            info.Postal = data.Postal

            // Парсим координаты из поля Loc
            if data.Loc != "" {
                parts := strings.Split(data.Loc, ",")
                if len(parts) == 2 {
                    fmt.Sscanf(parts[0], "%f", &info.Lat)
                    fmt.Sscanf(parts[1], "%f", &info.Lon)
                }
            }
        }
    }

    // HTTP проверка для домена
    httpClient := http.Client{
        Timeout: 10 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }

    httpResp, err := httpClient.Get("https://" + domain)
    if err != nil {
        httpResp, err = httpClient.Get("http://" + domain)
    }

    if err == nil && httpResp != nil {
        defer httpResp.Body.Close()
        info.HttpStatus = httpResp.StatusCode
        info.HttpStatusText = httpResp.Status
        info.WebServer = httpResp.Header.Get("Server")
    } else {
        info.HttpStatus = 0
        info.HttpStatusText = "Недоступен"
        info.WebServer = "—"
    }

    return info
}

func analyzeDNS(domain string, recordType string) (DNSResponse, error) {
    response := DNSResponse{
        Checks: make(map[string][]DNSCheckResult),
    }

    nsServers, err := getNSServers(domain)
    if err != nil {
        return response, err
    }
    response.NSServers = nsServers

    response.Zones = checkNSZones(domain, nsServers)

    var wg sync.WaitGroup
    var mu sync.Mutex

    // Ограничиваем количество одновременных запросов до 10
    semaphore := make(chan struct{}, 10)

    for _, dns := range dnsServers {
        wg.Add(1)
        go func(dnsIP, dnsName, country, flag, city string) {
            defer wg.Done()
            semaphore <- struct{}{}
            defer func() { <-semaphore }()

            records, responseTime, err := checkDNSOnServer(domain, recordType, dnsIP)

            location := country
            if city != "" {
                location = city + ", " + country
            }

            result := DNSCheckResult{
                DNSServer:    dnsIP,
                ServerName:   dnsName,
                Country:      location,
                CountryFlag:  flag,
                ResponseTime: responseTime,
            }

            if err != nil {
                if strings.Contains(err.Error(), "i/o timeout") {
                    result.Error = "Timeout"
                } else if strings.Contains(err.Error(), "no such host") {
                    result.Error = "No records"
                } else {
                    result.Error = "No response"
                }
            } else if len(records) == 0 {
                result.Error = "No records"
            } else {
                result.Records = records
            }

            mu.Lock()
            response.Checks[recordType] = append(response.Checks[recordType], result)
            mu.Unlock()
        }(dns.IP, dns.Name, dns.Country, dns.CountryFlag, dns.City)
    }

    wg.Wait()
    return response, nil
}

func handleAnalyze(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var request struct {
        Domain     string `json:"domain"`
        RecordType string `json:"record_type"`
    }

    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    rawDomain := strings.TrimSpace(request.Domain)
    if rawDomain == "" {
        http.Error(w, "Domain is required", http.StatusBadRequest)
        return
    }

    domainForDNS := toPunycode(rawDomain)

    recordType := strings.ToUpper(request.RecordType)
    if recordType == "" {
        recordType = "A"
    }

    var wg sync.WaitGroup
    var whoisInfo *WhoisInfo
    var whoisErr error
    var dnsResponse DNSResponse
    var dnsErr error
    var serverIP string

    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    wg.Add(1)
    go func() {
        defer wg.Done()
        select {
        case <-ctx.Done():
            whoisErr = ctx.Err()
        default:
            whoisInfo, whoisErr = getWhoisInfo(rawDomain)
        }
    }()

    wg.Add(1)
    go func() {
        defer wg.Done()
        select {
        case <-ctx.Done():
            dnsErr = ctx.Err()
        default:
            dnsResponse, dnsErr = analyzeDNS(domainForDNS, recordType)
        }
    }()

    wg.Add(1)
    go func() {
        defer wg.Done()
        select {
        case <-ctx.Done():
        default:
            ips, err := net.LookupIP(domainForDNS)
            if err == nil && len(ips) > 0 {
                for _, ip := range ips {
                    if ipv4 := ip.To4(); ipv4 != nil {
                        serverIP = ipv4.String()
                        break
                    }
                }
                if serverIP == "" {
                    serverIP = ips[0].String()
                }
            }
        }
    }()

    wg.Wait()

    serverInfo := getServerInfo(serverIP, rawDomain)

    response := AnalyzeResponse{
        Server: serverInfo,
    }

    if whoisErr != nil {
        response.WhoisError = whoisErr.Error()
    } else {
        response.Whois = *whoisInfo
    }

    if dnsErr != nil {
        response.ServerError = dnsErr.Error()
    } else {
        response.DNS = dnsResponse
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}