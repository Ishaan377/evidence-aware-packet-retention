# Working together

Read TEAM_START_HERE.md before editing. The main branch is the shared working version.

For code changes, make a short branch, change one thing, run `python -B run_project.py --check --no-open`, then open a pull request. A pull request is a reviewable proposal to add your changes to main. Ask another teammate to review it before merging.

GitHub Desktop offers this workflow without command-line Git: sign in, clone this repository, create a branch, edit files, review changes, commit, push and click Create Pull Request. Download it from https://desktop.github.com/.

For a simple documentation correction, GitHub's pencil button can propose an edit in a new branch. Do not edit a Word document by replacing its text in the browser; download and edit the DOCX, then upload the updated file in a review branch.

The automatic check runs the full synthetic demo, 15 unit tests and the 165-subset audit on Windows and Linux. Check the Actions tab for the actual status; having a workflow file alone does not prove it ran.

Save new experimental runs under results/ with a new name. These generated files are ignored by Git. Publish small, explicitly labelled representative examples under examples/ only after their code/configuration/data provenance and conclusions have been checked. Do not update a chart to show an outcome that was not measured.

Keep the original synopsis reference unchanged. The existing document builders are optional authoring utilities and need Python document/image packages; the core demo does not need them. Document visual checks additionally need the saved local render history described in logs/continuation_notes.md.

Record substantive changes and outcomes in logs/action_log.md. Update logs/continuation_notes.md when the project scope or current state changes. Git records source history; the action log explains decisions and verification.
