Output assets/ecr-prioritizer-demo.gif
Set Shell "bash"
Set FontSize 18
Set Width 1280
Set Height 900
Set TypingSpeed 45ms
Set PlaybackSpeed 0.75

Type "./bin/ecr-prioritizer --demo --limit 10"
Enter
Sleep 5s

Type "./bin/ecr-prioritizer --demo --format md --limit 4"
Enter
Sleep 6s

Type "./bin/ecr-prioritizer --demo --out-prefix demo-report --format table --limit 4"
Enter
Sleep 4s

Type "ls -1 demo-report.*"
Enter
Sleep 3s
