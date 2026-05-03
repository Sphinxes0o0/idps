# BPF source files (split architecture)
set(BPF_SOURCES
    nids_bpf_helpers.c
    nids_bpf_events.c
    nids_bpf_flow.c
    nids_bpf_parser.c
    nids_bpf_attack.c
    nids_bpf_defrag.c
    nids_bpf_proto.c
    nids_bpf_main.c
)

# For now, keep single file - will be split incrementally
# Once all modules split, replace nids_bpf.c with ${BPF_SOURCES}
