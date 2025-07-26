// main.rs

use iced::widget::{button, column, container, text, svg, row, toggler, progress_bar, Space};
use iced::{executor, theme, Application, Command, Element, Length, Settings, Theme, Subscription, Alignment, Background, Color, Gradient, Degrees, gradient, Border, Shadow};
use iced::time;
use iced::keyboard;
use std::time::Duration;

// --- Зависимости для сети, криптографии и QR-кодов ---
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use aes::Aes128;
use cbc::Decryptor;
use cbc::cipher::{KeyIvInit, BlockDecryptMut};
use block_padding::Pkcs7;
use qrcode_generator::QrCodeEcc;

// --- IP-адрес ESP32 в режиме точки доступа ---
const DEVICE_ADDRESS: &str = "192.168.4.1:80";

// --- Ключ для расшифровки AES (должен совпадать с ключом на ESP32) ---
const DECRYPTION_KEY: [u8; 16] = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
const IV: [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

type Aes128CbcDec = Decryptor<Aes128>;

// --- Кастомный шрифт ---
const GEIST_MONO: iced::Font = iced::Font::with_name("Geist Mono");

// --- SVG-данные для логотипа (встроенный) ---
const LOGO_SVG: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 16V12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 8H12.01" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>"#;


pub fn main() -> iced::Result {
    let mut settings = Settings::default();
    settings.fonts = vec![include_bytes!("../GeistMono-Regular.otf").as_slice().into()];
    TrngApp::run(settings)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppTheme {
    Light,
    Dark,
}

struct TrngApp {
    theme: AppTheme,
    status: String,
    generated_password: String,
    qr_code: Option<iced::widget::image::Handle>,
    connection_progress: f32,
    generation_progress: f32,
    is_connecting: bool,
    is_generating: bool,
}

#[derive(Debug, Clone)]
enum Message {
    ThemeChanged(bool),
    FontLoaded(Result<(), iced::font::Error>),
    Generate,
    ConnectionTick,
    GenerationTick,
    PasswordGenerated(Result<String, String>),
    RemoteControl(RemoteCommand),
    NoOp,
}

#[derive(Debug, Clone)]
enum RemoteCommand {
    Up,
    Down,
    Select,
}

impl Application for TrngApp {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (
            Self {
                theme: AppTheme::Dark,
                status: "Готово к подключению".to_string(),
                generated_password: String::new(),
                qr_code: None,
                connection_progress: 0.0,
                generation_progress: 0.0,
                is_connecting: false,
                is_generating: false,
            },
            iced::font::load(include_bytes!("../GeistMono-Regular.otf").as_slice()).map(Message::FontLoaded),
        )
    }

    fn title(&self) -> String { String::from("Ключник TRNG Client") }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::FontLoaded(_) => Command::none(),
            Message::ThemeChanged(is_dark) => {
                self.theme = if is_dark { AppTheme::Dark } else { AppTheme::Light };
                Command::none()
            }
            Message::Generate => {
                self.status = "Подключение...".to_string();
                self.is_connecting = true;
                self.is_generating = false;
                self.generated_password.clear();
                self.qr_code = None;
                self.connection_progress = 0.0;
                self.generation_progress = 0.0;
                Command::none()
            }
            Message::ConnectionTick => {
                if self.is_connecting {
                    self.connection_progress += 0.02;
                    if self.connection_progress >= 1.0 {
                        self.is_connecting = false;
                        self.is_generating = true;
                        self.status = "Генерация энтропии...".to_string();
                        return Command::perform(generate_password_async(), Message::PasswordGenerated);
                    }
                }
                Command::none()
            }
            Message::GenerationTick => {
                 if self.is_generating {
                    self.generation_progress += 0.05;
                    if self.generation_progress > 1.0 {
                        self.generation_progress = 1.0;
                    }
                }
                Command::none()
            }
            Message::PasswordGenerated(Ok(password)) => {
                self.status = "Пароль успешно сгенерирован!".to_string();
                self.generated_password = password.clone();
                let png_data = qrcode_generator::to_png_to_vec(password.as_bytes(), QrCodeEcc::Medium, 512).unwrap();
                let handle = iced::widget::image::Handle::from_memory(png_data);
                self.qr_code = Some(handle);
                self.is_connecting = false;
                self.is_generating = false;
                self.generation_progress = 1.0;
                Command::none()
            }
            Message::PasswordGenerated(Err(e)) => {
                self.status = format!("Ошибка: {}", e);
                self.is_connecting = false;
                self.is_generating = false;
                Command::none()
            }
            Message::RemoteControl(cmd) => {
                Command::perform(send_remote_command(cmd), |_| Message::NoOp)
            }
            Message::NoOp => Command::none(),
        }
    }
    
    fn subscription(&self) -> Subscription<Message> {
        let mut subs = vec![];
        subs.push(keyboard::on_key_press(|key, _modifiers| match key {
            keyboard::Key::Named(keyboard::key::Named::ArrowUp) => Some(Message::RemoteControl(RemoteCommand::Up)),
            keyboard::Key::Named(keyboard::key::Named::ArrowDown) => Some(Message::RemoteControl(RemoteCommand::Down)),
            keyboard::Key::Named(keyboard::key::Named::Enter) => Some(Message::RemoteControl(RemoteCommand::Select)),
            keyboard::Key::Character(s) if s == " " => Some(Message::RemoteControl(RemoteCommand::Select)),
            _ => None,
        }));
        if self.is_connecting {
            subs.push(time::every(Duration::from_millis(50)).map(|_| Message::ConnectionTick));
        }
        if self.is_generating {
             subs.push(time::every(Duration::from_millis(100)).map(|_| Message::GenerationTick));
        }
        Subscription::batch(subs)
    }

    fn view(&self) -> Element<Message> {
        let logo_path = format!("{}/logo.svg", env!("CARGO_MANIFEST_DIR"));
        let logo_handle = if std::path::Path::new(&logo_path).exists() {
            svg::Handle::from_path(logo_path)
        } else {
            svg::Handle::from_memory(LOGO_SVG.as_bytes())
        };
        
        // --- ИЗМЕНЕНИЕ: Размеры немного уменьшены для баланса ---
        let logo = svg(logo_handle)
            .width(Length::Fixed(80.0))
            .height(Length::Fixed(80.0))
            .style(theme::Svg::Custom(Box::new(InvertedLogoStyle::new(self.theme))));

        let logo_container = container(logo)
            .width(Length::Fixed(140.0))
            .height(Length::Fixed(140.0))
            .center_x()
            .center_y()
            .style(theme::Container::Custom(Box::new(LogoCircleStyle::new(self.theme))));

        let title = text("Ключник").size(40).font(GEIST_MONO);
        
        let theme_toggle = row![
            text("Light").size(16).font(GEIST_MONO),
            toggler(None, self.theme == AppTheme::Dark, Message::ThemeChanged).width(Length::Fixed(50.0)),
            text("Dark").size(16).font(GEIST_MONO)
        ]
        .spacing(10)
        .align_items(Alignment::Center);

        let remote_controls = container(column![
            text("Пульт").size(22).font(GEIST_MONO),
            Space::new(Length::Shrink, Length::Fixed(10.0)),
            button(text("▲").size(22)).on_press(Message::RemoteControl(RemoteCommand::Up)).width(Length::Fill).style(theme::Button::Secondary),
            button(text("▼").size(22)).on_press(Message::RemoteControl(RemoteCommand::Down)).width(Length::Fill).style(theme::Button::Secondary),
            button(text("Select").size(22)).on_press(Message::RemoteControl(RemoteCommand::Select)).width(Length::Fill).style(theme::Button::Secondary),
        ].spacing(10).align_items(Alignment::Center))
        .width(Length::Fixed(140.0))
        .padding(20)
        .style(theme::Container::Box);

        let top_bar = row![
            logo_container,
            Space::new(Length::Fill, Length::Shrink),
            title,
            Space::new(Length::Fill, Length::Shrink),
            remote_controls,
        ]
        .spacing(20)
        .padding(20)
        .align_items(Alignment::Center);

        let main_button_text = if self.is_connecting { "Подключение..." } else if self.is_generating { "Генерация..." } else { "Сгенерировать пароль" };
        let main_button = button(container(text(main_button_text).size(32).font(GEIST_MONO)).center_x().center_y())
            .padding(25)
            .style(if self.is_connecting || self.is_generating { theme::Button::Secondary } else { theme::Button::Primary })
            .on_press(Message::Generate);
        
        let status_area = if self.is_connecting || self.is_generating {
             column![
                text(&self.status).size(24).font(GEIST_MONO),
                progress_bar(0.0..=1.0, if self.is_connecting { self.connection_progress } else { self.generation_progress })
            ].spacing(20).align_items(Alignment::Center)
        } else {
            column![text(&self.status).size(24).font(GEIST_MONO)].spacing(20).align_items(Alignment::Center)
        };
        
        let password_display = container(text(&self.generated_password).size(48).font(GEIST_MONO))
            .style(theme::Container::Box)
            .padding(25);

        let qr_display: Element<_> = if let Some(handle) = self.qr_code.clone() {
            container(iced::widget::Image::new(handle).width(Length::Fill).height(Length::Fill)).into()
        } else {
            container(Space::new(Length::Fill, Length::Fill)).into()
        };

        let result_area = container(
            row![
                container(password_display).width(Length::Fill).center_x().center_y(),
                container(qr_display).width(Length::Fixed(300.0)).height(Length::Fixed(300.0)).padding(20)
            ].align_items(Alignment::Center)
        );

        let content = column![
            row![top_bar, theme_toggle].align_items(Alignment::Center).spacing(20),
            Space::new(Length::Shrink, Length::Fill),
            main_button,
            Space::new(Length::Shrink, Length::Fixed(40.0)),
            status_area,
            if !self.generated_password.is_empty() { result_area } else { container(Space::new(Length::Shrink, Length::Fixed(0.0))) },
            Space::new(Length::Shrink, Length::Fill),
        ]
        .spacing(20)
        .padding(20)
        .width(Length::Fill)
        .align_items(Alignment::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(theme::Container::Custom(Box::new(GradientBackground::new(self.theme))))
            .center_x()
            .center_y()
            .into()
    }
    
    fn theme(&self) -> Self::Theme {
        match self.theme {
            AppTheme::Light => Theme::custom(
                "Custom Light".to_string(),
                theme::Palette {
                    background: Color::from_rgb8(0xef, 0xf1, 0xf5),
                    text: Color::from_rgb8(0x4c, 0x4f, 0x69),
                    primary: Color::from_rgb8(0x1e, 0x66, 0xf5),
                    success: Color::from_rgb8(0x40, 0xa0, 0x2b),
                    danger: Color::from_rgb8(0xd2, 0x0f, 0x39),
                }
            ),
            AppTheme::Dark => Theme::custom(
                "Custom Dark".to_string(),
                theme::Palette {
                    background: Color::from_rgb8(0x1e, 0x1e, 0x2e),
                    text: Color::from_rgb8(0xcd, 0xd6, 0xf4),
                    primary: Color::from_rgb8(0xcb, 0xa6, 0xf7),
                    success: Color::from_rgb8(0xa6, 0xe3, 0xa1),
                    danger: Color::from_rgb8(0xf3, 0x8b, 0xa8),
                }
            ),
        }
    }
}

// --- Кастомный стиль для градиентного фона ---
#[derive(Debug, Clone, Copy)]
struct GradientBackground {
    theme: AppTheme,
}
impl GradientBackground {
    fn new(theme: AppTheme) -> Self { Self { theme } }
}
impl container::StyleSheet for GradientBackground {
    type Style = Theme;
    fn appearance(&self, _style: &Self::Style) -> container::Appearance {
        let colors = match self.theme {
            AppTheme::Dark => [Color::from_rgb8(0x1e, 0x1e, 0x2e), Color::from_rgb8(0x11, 0x11, 0x1b)],
            AppTheme::Light => [Color::from_rgb8(0xef, 0xf1, 0xf5), Color::from_rgb8(0xcc, 0xd0, 0xf4)],
        };
        
        let gradient = Gradient::Linear(
            gradient::Linear::new(Degrees(160.0))
                .add_stop(0.0, colors[0])
                .add_stop(1.0, colors[1]),
        );

        container::Appearance {
            background: Some(Background::Gradient(gradient)),
            ..Default::default()
        }
    }
}

// --- Кастомный стиль для контейнера логотипа ---
#[derive(Debug, Clone, Copy)]
struct LogoCircleStyle {
    theme: AppTheme,
}
impl LogoCircleStyle {
    fn new(theme: AppTheme) -> Self { Self { theme } }
}
impl container::StyleSheet for LogoCircleStyle {
    type Style = Theme;
    fn appearance(&self, _style: &Self::Style) -> container::Appearance {
        let colors = match self.theme {
            AppTheme::Dark => [Color::from_rgba8(0x31, 0x32, 0x44, 0.8), Color::from_rgba8(0x11, 0x11, 0x1b, 0.5)],
            AppTheme::Light => [Color::from_rgba8(0xcc, 0xcd, 0xd2, 0.8), Color::from_rgba8(0xef, 0xf1, 0xf5, 0.5)],
        };
        
        container::Appearance {
            background: Some(Background::Color(colors[0])),
            border: Border {
                color: colors[1],
                width: 2.0,
                radius: 70.0.into(), // Делаем контейнер круглым
            },
            shadow: Shadow {
                color: Color::from_rgba8(0, 0, 0, 0.25),
                offset: iced::Vector::new(0.0, 5.0),
                blur_radius: 10.0,
            },
            ..Default::default()
        }
    }
}

// --- Кастомный стиль для SVG-логотипа (эффект инверсии) ---
#[derive(Debug, Clone, Copy)]
struct InvertedLogoStyle {
    theme: AppTheme,
}
impl InvertedLogoStyle {
    fn new(theme: AppTheme) -> Self { Self { theme } }
}
impl svg::StyleSheet for InvertedLogoStyle {
    type Style = Theme;
    fn appearance(&self, style: &Self::Style) -> svg::Appearance {
        let palette = style.extended_palette();
        let color = match self.theme {
            AppTheme::Dark => Some(palette.primary.strong.color),
            AppTheme::Light => Some(palette.background.strong.text),
        };
        svg::Appearance { color }
    }
}


// --- Асинхронные функции (без изменений) ---
async fn generate_password_async() -> Result<String, String> {
    let mut stream = TcpStream::connect(DEVICE_ADDRESS).await.map_err(|e| format!("Не удалось подключиться: {}", e))?;
    stream.write_all(b"GET_DATA\n").await.map_err(|e| format!("Ошибка отправки запроса: {}", e))?;
    let mut buffer = [0; 256];
    let n = stream.read(&mut buffer).await.map_err(|e| format!("Ошибка чтения ответа: {}", e))?;
    let response = String::from_utf8_lossy(&buffer[..n]).to_string();
    let (len, complexity, encrypted_key_hex) = parse_response(&response)?;
    let mut encrypted_key_buf = hex::decode(encrypted_key_hex).map_err(|_| "Неверный формат HEX ключа".to_string())?;
    if encrypted_key_buf.len() != 32 { return Err(format!("Ожидалось 32 байта, получено {}", encrypted_key_buf.len())); }
    let cipher = Aes128CbcDec::new_from_slices(&DECRYPTION_KEY, &IV).map_err(|e| format!("Ошибка инициализации дешифратора: {}", e))?;
    let decrypted_key = cipher.decrypt_padded_mut::<Pkcs7>(&mut encrypted_key_buf).map_err(|e| format!("Ошибка расшифровки: {}", e))?;
    Ok(generate_password_from_bytes(decrypted_key, len, complexity))
}

fn parse_response(response: &str) -> Result<(usize, u8, &str), String> {
    let parts: Vec<&str> = response.trim().split(',').collect();
    if parts.len() != 3 { return Err(format!("Неверный формат ответа ({} частей)", parts.len())); }
    let len_part = parts[0].strip_prefix("LEN:").ok_or("Отсутствует LEN")?;
    let len = len_part.parse::<usize>().map_err(|_| "Неверное значение LEN")?;
    let complex_part = parts[1].strip_prefix("COMPLEX:").ok_or("Отсутствует COMPLEX")?;
    let complexity = complex_part.parse::<u8>().map_err(|_| "Неверное значение COMPLEX")?;
    let key_part = parts[2].strip_prefix("KEY:").ok_or("Отсутствует KEY")?;
    Ok((len, complexity, key_part))
}

fn generate_password_from_bytes(random_bytes: &[u8], length: usize, complexity: u8) -> String {
    const NUMBERS: &[u8] = b"0123456789";
    const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";
    let char_set = match complexity {
        0 => NUMBERS.to_vec(), 1 => LOWERCASE.to_vec(), 2 => UPPERCASE.to_vec(),
        3 => [LOWERCASE, UPPERCASE].concat(), 4 => [LOWERCASE, UPPERCASE, NUMBERS].concat(),
        _ => [LOWERCASE, UPPERCASE, NUMBERS, SYMBOLS].concat(),
    };
    let mut password = String::with_capacity(length);
    for &byte in random_bytes.iter().cycle().take(length) {
        password.push(char_set[byte as usize % char_set.len()] as char);
    }
    password
}

async fn send_remote_command(cmd: RemoteCommand) {
    if let Ok(mut stream) = TcpStream::connect(DEVICE_ADDRESS).await {
        let cmd_str = match cmd {
            RemoteCommand::Up => "CMD_UP\n",
            RemoteCommand::Down => "CMD_DOWN\n",
            RemoteCommand::Select => "CMD_SELECT\n",
        };
        let _ = stream.write_all(cmd_str.as_bytes()).await;
    }
}
