"""Create compact contact sheets from actual PDF page renders for visual QA."""
from pathlib import Path
from PIL import Image, ImageDraw
root=Path(__file__).resolve().parents[1]/'report'/'preview'
pages=sorted(root.glob('page-*.png'))
for start in range(0,len(pages),6):
    batch=pages[start:start+6]
    sheet=Image.new('RGB',(1200,3*590),'#d8dce2')
    draw=ImageDraw.Draw(sheet)
    for j,path in enumerate(batch):
        im=Image.open(path).convert('RGB'); im.thumbnail((570,550))
        x=(j%2)*600+15; y=(j//2)*590+25
        sheet.paste(im,(x,y)); draw.text((x,y-18),path.name,fill='black')
    sheet.save(root/f'contact-{start//6+1}.png')
