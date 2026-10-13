"""Verify published registration and inherited Train/Dev source bytes, without network."""
import json
import platform
from pathlib import Path
import torch
from chapter5.collect import c4_inputs
from chapter5.core import digest
from chapter5.io import read_json,sha_file


def main():
    root=Path('.')
    registration=read_json(root/'chapter5/registration.json')
    for path,expected in registration['files'].items():
        if sha_file(root/path)!=expected:
            raise ValueError('published registration mismatch: '+path)
    cfg=read_json(root/'chapter5/config.json')
    if digest(cfg)!=registration['config_sha256'] or platform.python_version()!='3.12.14' or torch.__version__!='2.9.1+cpu' or torch.cuda.is_available():
        raise ValueError('CPU configuration or dependency mismatch')
    contexts,targets,exposed,bindings=c4_inputs(root)
    print(json.dumps({'phase':'preflight_verified','bound_registration_files':len(registration['files']),
                      'inherited_source_bindings':len(bindings),'inherited_target_statements':len(targets),
                      'recorded_exposed_cves':len(exposed),'python':platform.python_version(),'torch':torch.__version__,
                      'old_test_gold_documents_opened':0,'model_api_calls':0}),flush=True)


if __name__=='__main__':
    main()
