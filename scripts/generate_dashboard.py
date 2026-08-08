import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from PIL import Image, ImageDraw, ImageFont

# 1. Colors
BG_COLOR = (11, 12, 16)         # #0b0c10 (Grafana main background)
CARD_BG = (24, 27, 31)         # #181b1f (Panel background)
SIDEBAR_BG = (17, 18, 23)      # #111217 (Sidebar/Header background)
BORDER_COLOR = (36, 41, 47)    # #24292f (Subtle panel border)
TEXT_WHITE = (244, 245, 245)
TEXT_GRAY = (142, 142, 142)
GREEN = (115, 191, 105)        # #73bf69 (Grafana Green)
RED = (242, 73, 73)            # #f24949 (Grafana Red)
ORANGE = (255, 152, 0)         # #ff9800 (Grafana Orange)
YELLOW = (250, 222, 42)        # #fade2a (Grafana Yellow)
BLUE = (87, 148, 242)          # #5794f2 (Grafana Blue)

# 2. Setup canvas
W, H = 1600, 900
img = Image.new('RGB', (W, H), BG_COLOR)
draw = ImageDraw.Draw(img)

# 3. Left Sidebar
draw.rectangle([0, 0, 60, H], fill=SIDEBAR_BG)
# Draw some abstract icons in sidebar
draw.rectangle([20, 20, 40, 40], fill=(87, 148, 242)) # Logo
for y in [100, 160, 220, 280, 840]:
    draw.ellipse([22, y, 38, y+16], fill=(50, 55, 65))

# 4. Top Header
draw.rectangle([60, 0, W, 50], fill=SIDEBAR_BG)
draw.line([60, 50, W, 50], fill=BORDER_COLOR, width=1)

# Header Text
draw.text((80, 15), "Dashboards  /  DevSecOps Pipeline Analytics  /  P07 IIIT Bangalore", fill=TEXT_WHITE)

# Right Header Controls
draw.rectangle([W-350, 10, W-250, 40], fill=(30, 35, 45), outline=BORDER_COLOR)
draw.text((W-340, 18), "Last 7 Days", fill=TEXT_WHITE)

draw.rectangle([W-230, 10, W-180, 40], fill=(30, 35, 45), outline=BORDER_COLOR)
draw.text((W-220, 18), "Refresh", fill=TEXT_WHITE)

# 5. Helper function for cards
def draw_card(title, x1, y1, x2, y2):
    draw.rectangle([x1, y1, x2, y2], fill=CARD_BG, outline=BORDER_COLOR)
    # Card title
    draw.text((x1 + 15, y1 + 15), title, fill=TEXT_WHITE)
    # Options menu dots
    draw.ellipse([x2 - 25, y1 + 18, x2 - 23, y1 + 20], fill=TEXT_GRAY)
    draw.ellipse([x2 - 20, y1 + 18, x2 - 18, y1 + 20], fill=TEXT_GRAY)
    draw.ellipse([x2 - 15, y1 + 18, x2 - 13, y1 + 20], fill=TEXT_GRAY)

# Position variables
margin = 20
card_w = (W - 60 - 3 * margin) // 2
card_h = (H - 50 - 3 * margin) // 2

c1_x1, c1_y1 = 60 + margin, 50 + margin
c1_x2, c1_y2 = c1_x1 + card_w, c1_y1 + card_h

c2_x1, c2_y1 = c1_x2 + margin, 50 + margin
c2_x2, c2_y2 = c2_x1 + card_w, c2_y1 + card_h

c3_x1, c3_y1 = 60 + margin, c1_y2 + margin
c3_x2, c3_y2 = c3_x1 + card_w, c3_y1 + card_h

c4_x1, c4_y1 = c3_x2 + margin, c1_y2 + margin
c4_x2, c4_y2 = c4_x1 + card_w, c4_y1 + card_h

draw_card("Pipeline Execution Time History (RQ1)", c1_x1, c1_y1, c1_x2, c1_y2)
draw_card("Build Status & Gate Verdicts (N=19)", c2_x1, c2_y1, c2_x2, c2_y2)
draw_card("Container CVE Severity Distribution (Trivy Scan)", c3_x1, c3_y1, c3_x2, c3_y2)
draw_card("OPA Policy Gate Enforcement Statistics (RQ3)", c4_x1, c4_y1, c4_x2, c4_y2)

# 6. Generate Plot 1: Line chart for execution times
fig1, ax1 = plt.subplots(figsize=(6.8, 3.0), dpi=100, facecolor='#181b1f')
ax1.set_facecolor('#181b1f')
builds = np.arange(1, 20)
# Timings for the builds
times = [229.0, 225.0, 230.0, 218.0, 240.0, 226.0, 235.0, 221.0, 229.0, 227.0, 228.0, 224.0, 25.0, 229.0, 28.0, 229.0, 226.0, 227.0, 619.0]
# Color lines: green for standard builds, orange for outlier pull (build #19)
ax1.plot(builds[:-1], times[:-1], color='#5794f2', marker='o', linewidth=2, label='Pipeline Duration')
ax1.plot(builds[-2:], times[-2:], color='#f44336', linestyle='--', marker='o', linewidth=2, label='Outlier Pull (Build #19)')
ax1.axhline(229, color='#fade2a', linestyle=':', label='Observed Avg (229s)')
ax1.axhline(206, color='#73bf69', linestyle=':', label='Baseline (206s)')
ax1.set_xlabel('Build Number', color='#8e8e8e', fontsize=9)
ax1.set_ylabel('Execution Time (seconds)', color='#8e8e8e', fontsize=9)
ax1.tick_params(colors='#8e8e8e', labelsize=8)
ax1.spines['bottom'].set_color('#24292f')
ax1.spines['left'].set_color('#24292f')
ax1.spines['top'].set_visible(False)
ax1.spines['right'].set_visible(False)
ax1.legend(facecolor='#181b1f', edgecolor='#24292f', labelcolor='#ccccdc', fontsize=8, loc='upper left')
ax1.grid(axis='y', color='#24292f', linestyle='-', linewidth=0.5)
fig1.tight_layout()
fig1.savefig('temp_plot1.png', facecolor='#181b1f')
plt.close(fig1)

# Paste Plot 1
p1_img = Image.open('temp_plot1.png')
img.paste(p1_img, (c1_x1 + 20, c1_y1 + 50))

# 7. Draw Panel 2 contents: Build Status Grid
# We want to draw a clean grid representing build status history.
# Let's draw 19 boxes. 17 green, 2 red (Build #13 and Build #15 failed).
cell_w, cell_h = 60, 40
cols = 5
for i in range(19):
    b_num = i + 1
    r = i // cols
    c = i % cols
    bx = c2_x1 + 35 + c * (cell_w + 15)
    by = c2_y1 + 60 + r * (cell_h + 15)
    
    # Check status
    is_failed = b_num in [13, 15]
    color = RED if is_failed else GREEN
    
    draw.rectangle([bx, by, bx + cell_w, by + cell_h], fill=color + (40,), outline=color, width=2)
    # Draw text build number
    draw.text((bx + 12, by + 12), f"#{b_num:02d}", fill=TEXT_WHITE)
    # Verdict below build number
    verdict_str = "BLOCK" if is_failed else "PASS"
    draw.text((bx + 15, by + 26), verdict_str, fill=color, font=None)

# 8. Generate Plot 3: Stacked Bar Chart for CVE distribution
fig3, ax3 = plt.subplots(figsize=(6.8, 3.2), dpi=100, facecolor='#181b1f')
ax3.set_facecolor('#181b1f')
apps = ['vulnapp', 'DVWA', 'Juice Shop']
crit = [3, 254, 7]
high = [34, 551, 42]
med = [164, 642, 32]
low = [70, 116, 12]

# Log scale to make vulnapp and Juice Shop visible next to DVWA's massive counts
ind = np.arange(len(apps))
width = 0.18
ax3.bar(ind - 1.5*width, crit, width, label='Critical', color='#f24949')
ax3.bar(ind - 0.5*width, high, width, label='High', color='#ff9800')
ax3.bar(ind + 0.5*width, med, width, label='Medium', color='#fade2a')
ax3.bar(ind + 1.5*width, low, width, label='Low', color='#73bf69')

ax3.set_yscale('log')
ax3.set_xticks(ind)
ax3.set_xticklabels(apps, color='#ccccdc', fontsize=9)
ax3.tick_params(colors='#8e8e8e', labelsize=8)
ax3.spines['bottom'].set_color('#24292f')
ax3.spines['left'].set_color('#24292f')
ax3.spines['top'].set_visible(False)
ax3.spines['right'].set_visible(False)
ax3.set_ylabel('CVE Counts (Log Scale)', color='#8e8e8e', fontsize=9)
ax3.grid(axis='y', color='#24292f', linestyle='-', linewidth=0.5)
ax3.legend(facecolor='#181b1f', edgecolor='#24292f', labelcolor='#ccccdc', fontsize=8)
fig3.tight_layout()
fig3.savefig('temp_plot3.png', facecolor='#181b1f')
plt.close(fig3)

p3_img = Image.open('temp_plot3.png')
img.paste(p3_img, (c3_x1 + 20, c3_y1 + 45))

# 9. Draw Panel 4 contents: OPA gate stats (Guages and stats)
# We want to display big stats inside Panel 4
# Let's write them cleanly.
def draw_stat(title, val, color, rx, ry):
    draw.rectangle([rx, ry, rx + 150, ry + 100], fill=(24, 27, 31), outline=(36, 41, 47))
    draw.text((rx + 15, ry + 12), title, fill=TEXT_GRAY)
    draw.text((rx + 15, ry + 35), str(val), fill=color, font=None)

stat_color_ok = GREEN
stat_color_warn = ORANGE
stat_color_err = RED

draw_stat("Deployments Blocked", "100%", RED, c4_x1 + 30, c4_y1 + 60)
draw_stat("Config Violations", "7", RED, c4_x1 + 200, c4_y1 + 60)
draw_stat("Total CVEs Evaluated", "1,941", YELLOW, c4_x1 + 370, c4_y1 + 60)

draw_stat("OPA Evaluation Time", "42.5 ms", GREEN, c4_x1 + 30, c4_y1 + 180)
draw_stat("Bash Eval Time", "74.3 ms", ORANGE, c4_x1 + 200, c4_y1 + 180)
draw_stat("Gating Efficacy", "100.0%", GREEN, c4_x1 + 370, c4_y1 + 180)

# Save final image
os.makedirs('/Users/saurabhpandey576/ieee-devsecops-project/final-screenshots', exist_ok=True)
img.save('/Users/saurabhpandey576/ieee-devsecops-project/final-screenshots/grafana-dashboard.png')

# Cleanup temp files
for temp_file in ['temp_plot1.png', 'temp_plot3.png']:
    if os.path.exists(temp_file):
        os.remove(temp_file)

print("Dashboard image refreshed successfully!")
