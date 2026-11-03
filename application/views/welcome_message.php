<?php
defined('BASEPATH') or exit('No direct script access allowed');
// The Welcome controller does not load the URL helper, so load it here.
if (!function_exists('base_url')) {
	$CI = &get_instance();
	$CI->load->helper('url');
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="theme-color" content="#0b6b38">
	<title>ChatApp – Simple one-to-one chat with instant push notifications</title>
	<meta name="description" content="ChatApp is a WhatsApp-style messenger for small groups of testers: text, photos, short videos and push notifications.">
	<style>
		:root {
			--ink: #0d2f2a;
			--muted: #4f6b66;
			--paper: #f2f6f3;
			--card: #ffffff;
			--line: #d5e2dc;
			--green: #128c4a;
			--green-dark: #0b6b38;
			--bubble-out: #d9f5c9;
			--bubble-in: #ffffff;
			--chat-bg: #e7efe9;
			--amber: #f5a524;
		}

		@media (prefers-color-scheme: dark) {
			:root {
				--ink: #e6f2ee;
				--muted: #9bb5ae;
				--paper: #0e1b18;
				--card: #142622;
				--line: #24403a;
				--green: #2fbf71;
				--green-dark: #1f9a58;
				--bubble-out: #14503a;
				--bubble-in: #1b302b;
				--chat-bg: #0f201c;
			}
		}

		* {
			box-sizing: border-box;
			margin: 0;
			padding: 0
		}

		html {
			scroll-behavior: smooth
		}

		body {
			font-family: "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, Roboto, "Helvetica Neue", Arial, sans-serif;
			background: var(--paper);
			color: var(--ink);
			line-height: 1.6;
			-webkit-font-smoothing: antialiased;
		}

		a {
			color: inherit
		}

		:focus-visible {
			outline: 3px solid var(--amber);
			outline-offset: 3px;
			border-radius: 6px
		}

		.wrap {
			max-width: 1080px;
			margin: 0 auto;
			padding: 0 24px
		}

		/* top bar */
		.top {
			display: flex;
			align-items: center;
			justify-content: space-between;
			padding: 20px 0
		}

		.brand {
			display: flex;
			align-items: center;
			gap: 10px;
			font-weight: 700;
			font-size: 1.1rem;
			text-decoration: none
		}

		.logo {
			width: 34px;
			height: 34px;
			border-radius: 10px;
			background: var(--green);
			display: grid;
			place-items: center
		}

		.top nav a {
			margin-left: 22px;
			text-decoration: none;
			color: var(--muted);
			font-size: .95rem
		}

		.top nav a:hover {
			color: var(--ink)
		}

		/* hero */
		.hero {
			display: grid;
			grid-template-columns: 1.1fr .9fr;
			gap: 48px;
			align-items: center;
			padding: 48px 0 72px
		}

		h1 {
			font-size: clamp(2.3rem, 5.4vw, 3.9rem);
			line-height: 1.05;
			letter-spacing: -.035em;
			font-weight: 800;
			max-width: 13ch;
		}

		.lead {
			margin-top: 22px;
			font-size: 1.15rem;
			color: var(--muted);
			max-width: 46ch
		}

		.actions {
			margin-top: 32px;
			display: flex;
			flex-wrap: wrap;
			gap: 14px;
			align-items: center
		}

		.btn {
			display: inline-flex;
			align-items: center;
			gap: 10px;
			padding: 14px 22px;
			border-radius: 14px;
			font-weight: 650;
			text-decoration: none;
			font-size: 1rem;
			border: 2px solid transparent;
			transition: transform .15s ease, background .15s ease;
		}

		.btn.primary {
			background: var(--green);
			color: #fff
		}

		.btn.primary:hover {
			background: var(--green-dark);
			transform: translateY(-1px)
		}

		.btn.ghost {
			border-color: var(--line);
			color: var(--ink)
		}

		.btn.ghost:hover {
			border-color: var(--green)
		}

		.hint {
			margin-top: 14px;
			font-size: .88rem;
			color: var(--muted)
		}

		/* phone */
		.stage {
			display: flex;
			justify-content: center
		}

		.phone {
			position: relative;
			width: min(330px, 100%);
			aspect-ratio: 9/18.5;
			border-radius: 38px;
			background: #101a18;
			padding: 10px;
			box-shadow: 0 30px 60px -25px rgba(8, 40, 30, .55);
		}

		.screen {
			height: 100%;
			border-radius: 29px;
			overflow: hidden;
			background: var(--chat-bg);
			display: flex;
			flex-direction: column;
			position: relative
		}

		.bar {
			background: var(--green-dark);
			color: #fff;
			padding: 26px 16px 12px;
			display: flex;
			align-items: center;
			gap: 10px
		}

		.avatar {
			width: 36px;
			height: 36px;
			border-radius: 50%;
			background: #bfe8d1;
			color: #0b4a28;
			display: grid;
			place-items: center;
			font-weight: 700
		}

		.bar b {
			display: block;
			font-size: .95rem;
			line-height: 1.2
		}

		.bar small {
			font-size: .74rem;
			opacity: .85
		}

		.msgs {
			flex: 1;
			padding: 14px 12px;
			display: flex;
			flex-direction: column;
			gap: 8px;
			overflow: hidden
		}

		.m {
			max-width: 78%;
			padding: 8px 11px;
			border-radius: 12px;
			font-size: .86rem;
			line-height: 1.4;
			position: relative;
			color: #13251f
		}

		.m.in {
			background: var(--bubble-in);
			align-self: flex-start;
			border-top-left-radius: 3px
		}

		.m.out {
			background: var(--bubble-out);
			align-self: flex-end;
			border-top-right-radius: 3px
		}

		@media (prefers-color-scheme: dark) {
			.m {
				color: #e6f2ee
			}
		}

		.m time {
			display: flex;
			justify-content: flex-end;
			align-items: center;
			gap: 3px;
			font-size: .66rem;
			opacity: .65;
			margin-top: 2px
		}

		.photo {
			width: 170px;
			height: 96px;
			border-radius: 8px;
			margin-bottom: 5px;
			background: linear-gradient(160deg, #7cc9a2 0%, #3b9b78 45%, #1d5f55 100%);
			position: relative;
			overflow: hidden
		}

		.photo::after {
			content: "";
			position: absolute;
			left: -10%;
			bottom: -30%;
			width: 70%;
			height: 90%;
			border-radius: 50%;
			background: #e9f7ee;
			opacity: .28
		}

		.photo::before {
			content: "";
			position: absolute;
			right: 16px;
			top: 14px;
			width: 20px;
			height: 20px;
			border-radius: 50%;
			background: #ffe9a8
		}

		.input {
			margin: 8px;
			border-radius: 22px;
			background: var(--card);
			padding: 9px 14px;
			font-size: .82rem;
			color: var(--muted)
		}

		.push {
			position: absolute;
			left: 10px;
			right: 10px;
			top: 10px;
			background: var(--card);
			color: var(--ink);
			border-radius: 16px;
			padding: 10px 12px;
			display: flex;
			gap: 10px;
			align-items: center;
			box-shadow: 0 12px 30px -8px rgba(0, 0, 0, .4);
			transform: translateY(-130%);
			animation: drop .6s cubic-bezier(.2, .9, .3, 1.2) 1.4s forwards;
		}

		.push .logo {
			width: 28px;
			height: 28px;
			border-radius: 8px;
			flex: none
		}

		.push b {
			font-size: .8rem;
			display: block;
			line-height: 1.2
		}

		.push span {
			font-size: .76rem;
			color: var(--muted)
		}

		@keyframes drop {
			to {
				transform: translateY(0)
			}
		}

		@media (prefers-reduced-motion: reduce) {
			.push {
				animation: none;
				transform: none
			}
		}

		/* features */
		section {
			padding: 64px 0;
			border-top: 1px solid var(--line)
		}

		h2 {
			font-size: clamp(1.6rem, 3vw, 2.1rem);
			letter-spacing: -.02em;
			line-height: 1.15;
			max-width: 22ch
		}

		.feats {
			margin-top: 34px;
			display: grid;
			grid-template-columns: repeat(3, 1fr);
			gap: 0
		}

		.feat {
			padding: 0 28px 0 0
		}

		.feat+.feat {
			padding-left: 28px;
			border-left: 1px solid var(--line)
		}

		.feat h3 {
			font-size: 1.1rem;
			margin-bottom: 8px
		}

		.feat p {
			color: var(--muted);
			font-size: .98rem
		}

		.feat ul {
			margin-top: 12px;
			list-style: none;
			color: var(--muted);
			font-size: .93rem
		}

		.feat li {
			padding: 3px 0 3px 18px;
			position: relative
		}

		.feat li::before {
			content: "";
			position: absolute;
			left: 0;
			top: .85em;
			width: 7px;
			height: 7px;
			border-radius: 50%;
			background: var(--green)
		}

		/* steps */
		.steps {
			margin-top: 30px;
			display: grid;
			gap: 18px;
			max-width: 680px;
			counter-reset: s
		}

		.steps li {
			list-style: none;
			display: flex;
			gap: 16px;
			align-items: flex-start;
			counter-increment: s
		}

		.steps li::before {
			content: counter(s);
			flex: none;
			width: 32px;
			height: 32px;
			border-radius: 50%;
			background: var(--green);
			color: #fff;
			display: grid;
			place-items: center;
			font-weight: 700;
			font-size: .9rem
		}

		.steps b {
			display: block
		}

		.steps span {
			color: var(--muted);
			font-size: .96rem
		}

		/* api */
		.base {
			margin-top: 22px;
			display: inline-block;
			padding: 10px 14px;
			border-radius: 10px;
			background: var(--card);
			border: 1px solid var(--line);
			font-family: Consolas, "Cascadia Mono", monospace;
			font-size: .92rem;
			word-break: break-all
		}

		.tbl {
			margin-top: 26px;
			width: 100%;
			border-collapse: collapse;
			font-size: .93rem
		}

		.tbl th,
		.tbl td {
			text-align: left;
			padding: 10px 12px;
			border-bottom: 1px solid var(--line);
			vertical-align: top
		}

		.tbl th {
			font-weight: 650;
			color: var(--muted);
			font-size: .85rem
		}

		.tbl code {
			font-family: Consolas, "Cascadia Mono", monospace;
			font-size: .88rem
		}

		.v {
			display: inline-block;
			min-width: 46px;
			text-align: center;
			border-radius: 6px;
			padding: 1px 8px;
			font-size: .76rem;
			font-weight: 700;
			color: #fff
		}

		.v.get {
			background: #2f7fd1
		}

		.v.post {
			background: var(--green-dark)
		}

		.tw {
			overflow-x: auto
		}

		footer {
			padding: 34px 0 46px;
			border-top: 1px solid var(--line);
			color: var(--muted);
			font-size: .9rem;
			display: flex;
			flex-wrap: wrap;
			gap: 8px 24px;
			justify-content: space-between
		}

		@media (max-width:860px) {
			.hero {
				grid-template-columns: 1fr;
				gap: 36px;
				padding: 16px 0 48px
			}

			.stage {
				order: -1
			}

			h1 {
				max-width: none
			}

			.lead {
				max-width: none
			}

			.feats {
				grid-template-columns: 1fr;
				gap: 32px
			}

			.feat,
			.feat+.feat {
				padding: 0;
				border-left: 0
			}

			.feat+.feat {
				padding-top: 32px;
				border-top: 1px solid var(--line)
			}

			section {
				padding: 48px 0
			}
		}

		@media (max-width:640px) {
			.wrap {
				padding: 0 18px
			}

			.top {
				padding: 14px 0
			}

			.top nav a {
				margin-left: 16px
			}

			.top nav a:first-child {
				display: none
			}

			.phone {
				width: min(290px, 100%);
				border-radius: 34px
			}

			.screen {
				border-radius: 25px
			}

			.actions {
				flex-direction: column;
				align-items: stretch;
				gap: 12px
			}

			.btn {
				justify-content: center;
				padding: 16px 22px;
				min-height: 52px
			}

			.hint {
				text-align: center
			}

			.steps li {
				gap: 14px
			}

			/* API table becomes a simple list on small screens */
			.tbl thead {
				display: none
			}

			.tbl,
			.tbl tbody {
				display: block
			}

			.tbl tr {
				display: grid;
				grid-template-columns: auto 1fr;
				gap: 4px 12px;
				align-items: center;
				padding: 14px 0;
				border-bottom: 1px solid var(--line)
			}

			.tbl td {
				border: 0;
				padding: 0
			}

			.tbl td:nth-child(3) {
				grid-column: 1 / -1;
				color: var(--muted)
			}

			.base {
				display: block;
				font-size: .84rem
			}

			footer {
				flex-direction: column;
				padding-bottom: 36px
			}
		}

		@media (max-width:360px) {
			h1 {
				font-size: 2rem
			}

			.phone {
				width: 260px
			}
		}
	</style>
</head>

<body>
	<div class="wrap">
		<header class="top">
			<a class="brand" href="<?php echo base_url(); ?>">
				<span class="logo" aria-hidden="true">
					<svg width="20" height="20" viewBox="0 0 24 24" fill="#fff">
						<path d="M12 3C6.9 3 3 6.6 3 11.2c0 2.2 1 4.2 2.6 5.6L5 21l4.1-1.9c.9.2 1.9.4 2.9.4 5.1 0 9-3.600 9-8.300S17.100 3 12 3z" />
					</svg>
				</span>
				ChatApp
			</a>
			<nav>
				<a href="#features">Features</a>
				<a href="#start">Get started</a>
				<a href="#api">API</a>
			</nav>
		</header>

		<main>
			<div class="hero">
				<div>
					<h1>Chat with your friends. Get notified instantly.</h1>
					<p class="lead">A simple one-to-one messenger for small groups. Send texts, photos and short videos, and see when your message is delivered and read.</p>
					<div class="actions">
						<a class="btn primary" href="<?php echo base_url('downloads/chatapp.apk'); ?>" download>
							<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
								<path d="M12 4v11m0 0l-4-4m4 4l4-4M5 20h14" />
							</svg>
							Download for Android
						</a>
						<a class="btn ghost" href="#start">How to install</a>
					</div>
					<p class="hint">Android 7.0 or newer. Free to use during testing.</p>
				</div>

				<div class="stage" aria-hidden="true">
					<div class="phone">
						<div class="screen">
							<div class="bar">
								<div class="avatar">A</div>
								<div><b>Aarav</b><small>online</small></div>
							</div>
							<div class="msgs">
								<div class="m in">Did the notification reach your phone?<time>10:41</time></div>
								<div class="m out">Yes! It popped up right away.<time>10:41
										<svg width="16" height="10" viewBox="0 0 16 10" fill="none" stroke="#2a9de0" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
											<path d="M1 5.500l2.500 2.500L9 2M6 7.500l.5.500L12 2" />
										</svg></time></div>
								<div class="m in">
									<div class="photo"></div>Look at this view<time>10:42</time>
								</div>
								<div class="m out">Wow, send more!<time>10:42
										<svg width="16" height="10" viewBox="0 0 16 10" fill="none" stroke="#2a9de0" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
											<path d="M1 5.500l2.500 2.500L9 2M6 7.500l.5.500L12 2" />
										</svg></time></div>
							</div>
							<div class="input">Type a message</div>
							<div class="push">
								<span class="logo"><svg width="16" height="16" viewBox="0 0 24 24" fill="#fff">
										<path d="M12 3C6.9 3 3 6.600 3 11.200c0 2.200 1 4.200 2.600 5.600L5 21l4.100-1.900c.9.200 1.900.400 2.900.400 5.100 0 9-3.600 9-8.300S17.100 3 12 3z" />
									</svg></span>
								<div><b>Riya</b><span>Sent you a photo</span></div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</main>

		<section id="features">
			<h2>Everything you need for a quick conversation</h2>
			<div class="feats">
				<div class="feat">
					<h3>Share what you see</h3>
					<p>Send messages, photos and short videos in a private chat with one person.</p>
					<ul>
						<li>Photos and videos up to 2 MB</li>
						<li>Add a caption to any media</li>
					</ul>
				</div>
				<div class="feat">
					<h3>Know it arrived</h3>
					<p>Ticks show when your message is sent, delivered and read. See who is online and when they were last seen.</p>
				</div>
				<div class="feat">
					<h3>Never miss a message</h3>
					<p>Push notifications reach your phone even when the app is closed, and tapping one opens the right chat.</p>
					<ul>
						<li>Alerts when a new person joins</li>
						<li>Works on all your signed-in devices</li>
					</ul>
				</div>
			</div>
		</section>

		<section id="start">
			<h2>Start chatting in three steps</h2>
			<ol class="steps">
				<li>
					<div><b>Download the app</b><span>Tap Download for Android above. If your phone asks, allow installs from this source.</span></div>
				</li>
				<li>
					<div><b>Create your account</b><span>Sign up with your email or mobile number and a password.</span></div>
				</li>
				<li>
					<div><b>Allow notifications</b><span>Say yes when asked, so new messages reach you right away.</span></div>
				</li>
			</ol>
		</section>

		<section id="api">
			<h2>For developers: API endpoints</h2>
			<p class="lead" style="font-size:1rem;margin-top:14px">Every endpoint returns JSON. Except register, login and forgot password, send your token in the Authorization header as <code>Bearer &lt;token&gt;</code>.</p>
			<div class="base"><?php echo base_url('api/'); ?></div>
			<div class="tw">
				<table class="tbl">
					<thead>
						<tr>
							<th>Method</th>
							<th>Endpoint</th>
							<th>What it does</th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td><span class="v post">POST</span></td>
							<td><code>register</code></td>
							<td>Create an account and get a token</td>
						</tr>
						<tr>
							<td><span class="v post">POST</span></td>
							<td><code>login</code></td>
							<td>Sign in with email or mobile</td>
						</tr>
						<tr>
							<td><span class="v post">POST</span></td>
							<td><code>logout</code></td>
							<td>Sign out and remove this device's token</td>
						</tr>
						<tr>
							<td><span class="v get">GET</span></td>
							<td><code>profile</code></td>
							<td>Get your profile</td>
						</tr>
						<tr>
							<td><span class="v post">POST</span></td>
							<td><code>update_profile</code></td>
							<td>Change name, about, email, mobile or password</td>
						</tr>
						<tr>
							<td><span class="v post">POST</span></td>
							<td><code>update_profile_image</code></td>
							<td>Upload a profile photo</td>
						</tr>
						<tr>
							<td><span class="v post">POST</span></td>
							<td><code>save_token</code></td>
							<td>Register the phone for push notifications</td>
						</tr>
						<tr>
							<td><span class="v get">GET</span></td>
							<td><code>users</code></td>
							<td>List people you can chat with</td>
						</tr>
						<tr>
							<td><span class="v get">GET</span></td>
							<td><code>conversations</code></td>
							<td>Chat list with last message and unread count</td>
						</tr>
						<tr>
							<td><span class="v get">GET</span></td>
							<td><code>messages</code></td>
							<td>Load a chat, or only new messages with after_id</td>
						</tr>
						<tr>
							<td><span class="v post">POST</span></td>
							<td><code>send_message</code></td>
							<td>Send a text message</td>
						</tr>
						<tr>
							<td><span class="v post">POST</span></td>
							<td><code>send_media</code></td>
							<td>Send a photo or video (2 MB max)</td>
						</tr>
						<tr>
							<td><span class="v post">POST</span></td>
							<td><code>mark_read</code></td>
							<td>Mark a chat as read</td>
						</tr>
						<tr>
							<td><span class="v post">POST</span></td>
							<td><code>heartbeat</code></td>
							<td>Keep your online status current</td>
						</tr>
						<tr>
							<td><span class="v get">GET</span></td>
							<td><code>user_status</code></td>
							<td>Check if someone is online</td>
						</tr>
					</tbody>
				</table>
			</div>
		</section>

		<footer>
			<span>&copy; <?php echo date('Y'); ?> ChatApp</span>
			<span>Built with CodeIgniter, React Native and Firebase Cloud Messaging</span>
		</footer>
	</div>
</body>

</html>