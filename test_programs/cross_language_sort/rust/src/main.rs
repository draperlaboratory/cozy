/*
#[inline(never)]
extern "C" fn insertion_sort(p: &mut [i32]) {
    let n = p.len();
    for i in 1..n {
        let tmp = p[i];
        let mut j = i;
        while j > 0 && p[j-1] > tmp {
            p[j] = p[j-1];
            j -= 1;
        }
        p[j] = tmp;
    }
}
*/

#[inline(never)]
extern "C" fn bubble_sort(p: &mut [i32]) {
    let n = p.len();
    let mut swapped = true;
    while swapped {
        swapped = false;
        for i in 1 .. n {
            if p[i-1] > p[i] {
                let tmp = p[i-1];
                p[i-1] = p[i];
                p[i] = tmp;
                swapped = true;
            }
        }
    }
}

fn read_number() -> Option<i32> {
    let mut buffer = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut buffer).ok()?;
    return buffer.trim().parse::<i32>().ok();
}

fn main() {
    let mut numbers: Vec<i32> = Vec::new();
    loop {
        if let Some(n) = read_number() {
            numbers.push(n);
        } else {
            break;
        }
    }
    bubble_sort(numbers.as_mut_slice());

    for n in &numbers {
        println!("{0}", n);
    }
}
