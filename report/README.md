# Project documents

- `EBR_Complete_Guide.pdf`: the full project explained for complete beginners.
- `EBR_IEEE_Paper.pdf`: the research paper in IEEE conference format.
- `source/`: the LaTeX sources of both.

## To change and rebuild

The paper's author block is near the top of `source/paper/paper.tex`, and its AI-use disclosure is in the Acknowledgment section. Rebuilding the PDFs on Windows requires MiKTeX.

```powershell
powershell -ExecutionPolicy Bypass -File report\source\paper\build.ps1
powershell -ExecutionPolicy Bypass -File report\source\guide\build.ps1 -Runs 3
```

This writes `paper.pdf` and `guide.pdf` beside the sources. Copy them here to replace the published versions. The installer is switched off during builds, so nothing is downloaded.
