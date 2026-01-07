
uvicorn main:app --host 0.0.0.0 --port 6106 --reload



gunicorn -k uvicorn.workers.UvicornWorker main:app \
	  --bind 0.0.0.0:6106 \
	    --workers 4 \
	      --timeout 120 \
	        --keep-alive 5

