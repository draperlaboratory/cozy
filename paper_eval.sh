echo "name,pre_time(s),post_time(s),comp_time(s),num_pre_states,num_post_states,passed" > "eval_results.csv"
python3 examples/paper_eval/retrowrite.py base64_decode_alloc_ctx
python3 examples/paper_eval/retrowrite.py base64_decode_ctx
python3 examples/paper_eval/retrowrite.py base64_decode_ctx_init
python3 examples/paper_eval/retrowrite.py base64_encode_alloc
python3 examples/paper_eval/retrowrite.py base64_encode
python3 examples/paper_eval/retrowrite.py clone_quoting_options
python3 examples/paper_eval/retrowrite.py close_stdout
python3 examples/paper_eval/retrowrite.py close_stdout_set_file_name
python3 examples/paper_eval/retrowrite.py close_stdout_set_ignore_EPIPE
python3 examples/paper_eval/retrowrite.py close_stream
python3 examples/paper_eval/retrowrite.py decode_4
python3 examples/paper_eval/retrowrite.py deregister_tm_clones
python3 examples/paper_eval/retrowrite.py fadvise
python3 examples/paper_eval/retrowrite.py get_quoting_style
python3 examples/paper_eval/retrowrite.py isbase64