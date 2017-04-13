a=1;
for i in Virus*; do
  new=$(printf "%04d" "$a")
  mv -i -- "$i" "$new"
  let a=a+1
done
