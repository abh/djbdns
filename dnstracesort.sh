
sort -t: +0 -2 +4 +3 -4 +2 -3 | awk -F: '
  {
    if ($5 == "A") next
    if ($5 == "NS") next
    if ($5 == "tx") next

    type = $1
    q = $2
    c = $3
    ip = sprintf("%-16s",$4)

    if (q != lastq) { print ""; lastq = q }

    if ($5 == "ALERT") {
      result = "A\bAL\bLE\bER\bRT\bT:\b: " $6
    }
    else if ($5 == "answer") {
      if (index($6,q" ") == 1)
	$6 = substr($6,length(q) + 2)
      result = $6
    }
    else if ($5 == "see") {
      result = "see " $6
    }
    else if ($5 == "CNAME") {
      result = "CNAME "$6
    }
    else
      result = $5

    if (c != ".") {
      q = substr(q,1,length(q) - length(c))
      for (i = 1;i <= length(c);++i) {
	ci = substr(c,i,1)
	q = q "_\b" ci
      }
    }

    print type,q,ip,result
  }
'
