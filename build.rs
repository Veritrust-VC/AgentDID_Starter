#[cfg(all(windows, feature = "winres"))]
fn main() {
    let mut res = winres::WindowsResource::new();
    res.set("FileDescription", "AgentDID Starter by Veritrust");
    res.set("ProductName", "AgentDID Starter by Veritrust");
    // Optional: res.set_icon("assets/app.ico");
    res.compile().expect("failed to compile Windows resources");
}

#[cfg(not(all(windows, feature = "winres")))]
fn main() {}
