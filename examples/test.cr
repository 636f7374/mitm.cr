require "../src/mitm.cr"
require "http/server"

OpenSSL::X509::SuperRequest.new

dsa = OpenSSL::PKey::DSA.new bits: 4096_i32
STDOUT.puts [dsa.private_key?.try &.to_s, dsa.public_key?.try &.to_s]

rsa = OpenSSL::PKey::RSA.new bits: 4096_i32
STDOUT.puts [rsa.private_key?.try &.to_s, rsa.public_key?.try &.to_s]

certificate = Base64.decode "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUpsVENDQlgyZ0F3SUJBZ0lKQU5paVYrR0YzaHM2TUEwR0NTcUdTSWIzRFFFQkN3VUFNR0V4Q3pBSkJnTlYKQkFZVEFrWkpNUW93Q0FZRFZRUUlEQUVnTVFvd0NBWURWUVFIREFFZ01Rb3dDQVlEVlFRS0RBRWdNUW93Q0FZRApWUVFMREFFZ01SQXdEZ1lEVlFRRERBZEdhVzVzWVc1a01SQXdEZ1lKS29aSWh2Y05BUWtCRmdFZ01CNFhEVEU1Ck1EWXpNREE0TWpJeE5Gb1hEVEl4TURZeU9UQTRNakl4TkZvd1lURUxNQWtHQTFVRUJoTUNSa2t4Q2pBSUJnTlYKQkFnTUFTQXhDakFJQmdOVkJBY01BU0F4Q2pBSUJnTlZCQW9NQVNBeENqQUlCZ05WQkFzTUFTQXhFREFPQmdOVgpCQU1NQjBacGJteGhibVF4RURBT0Jna3Foa2lHOXcwQkNRRVdBU0F3Z2dRaU1BMEdDU3FHU0liM0RRRUJBUVVBCkE0SUVEd0F3Z2dRS0FvSUVBUUQrOFE0ODJwOVYxMVVsZXVqYndZQWpHd1RXMXVWaS9SVFk5d3lxZ2JQOHBLbGkKOWkrRVpJckNTUllZaWlxRnFGTUdKQnFuTi9VNGNYZk95elp1SEh2bUYybGVQTkZ1cFBxcDlNUHVUcGlHbEpHZQplMVRZeVlaTTNSVU1VMk1UZHVZVzl6dzdKSURLOTM5VThhbjFYZlRMR3E0R0NMV1c3MENTdTRZQjVLby9SZkcwCnp4UkRVaVZwOWJpZ3FGdzBESkZWTFo3b05MMFltQW42dlg2eGIvWmxnV0RkTGFBZHI0L1BhL3RNM1Z1dzRoTDYKQnF4S0kySGRheHFOUnh6ZFhXOVhoVXJtbkNTU1oyNmVWbGhGUVM2QklQTlVtZng1aWlwZ3Y3Tks5cEVYbUpIeApUb1ljTzBScGhJVllhY1hmMGhKejJmZmJJZ0lWekxNRWIveXMvZFNwQUdIZEYxK3hiYUFaM3dQZTJvcm5OQ0F0CnlKSXltRXZ0Vjlmb09TVTJ1RWZKOUlWZ2NuRW56eWl2Z2tQaDBuc0JMc0RWaW9KYUUzVHhRZlBzbmdBZ2QwdGIKMXpianRWVXc0MGN0UmxQak9XM2phb2ROdGYwd0pYZ3RjTHFncDVCVWlNZGJ0NHIxMnFTSVc3akhTSUd4blRsVgo3aWo3YnNTZkRVb29QaW5CVmhXYUlBS0ZCUzh3SzJrUEk4TnM5bVZvNVc0M0Vra2F2ZnN2dUhYZkZVSFhSMFBxCnh2SGE3cU56SnBNc0cvMG1heDN6eFpIWUEyL1B4MERySjNDOXBnb2U4UE5vLytQdk1qS2tESkFPN3I0UmN3UlYKNlJCYWFXS1duS3pYN05LYWNML3IwT2pSQkVBWUttQTNzSkRTUDNPeW8yVmFnTHhPUWp0dTlKZlNjMUNacTlIcQpPRkFKWm5DWGYvaG9ESWJtQ2tyOEg0V3lPL21WRzdzYTRFZ2cvbHF5VnBmdDh2RlpHN1VRenBnZUUycHkwcnhTClFVOXBLeU94dUczc1pxb0hWYS9PYWdIZzh0bE5CaXp3UjhZVDFWTW1rL2FXQ3hGNm5TNDdkdS8zKzNKczZCQk4KNzlPdGtXQzQrcEdscnp3M2dXbW1weEdZdEQ0L2hVY2ZnSysrR2tJd1RQVE1xU1g1K0d0OThtL09kT2FkQWhwZgplSXNZMDQ4U1d4UkhGQVdGbVQ1OE53MEpHbXRpa2hESjE0SmloMVNFRDdhUEp0ZmNiWThwREk0RUY0S3FXTUxlCkZkN0pMQVN6Y2h3TSttY1hzWFVhQVhXOTBONnpFWmkwUEMzYk9zc0FSNnp0TWZ0SUZUb2dKVFJLUCs5cGk5T2QKUmZmeVNGTlFpUHhlaEdoTktldG9ENkdaYlhIUllXRm5HYlh1NlNHTmlabnhEUnZJTDVPRlc3bkthR1ZTZTRoRApmUjRIencxU1RoYmJaLzR1dFJlOEFoRmRFTWMrMVp4M1lmRnV2LzZBWWd0MXVYTUJ2WEpSbFd6L0ZOSGR2cnI3Clc5TGdOaVRId2ZTUm10b3VLcXdKNEdKMmc1VDhsY0pRVU5oWXg3aWk0QzF6MFQwVjlNVko2QzdjcnplTlM5WlkKdUdLUExpL2JTWkVyY2V1eHF4anBFUE9EUzRJaHJnd08xSEJwSmJ4Rjg3YVhEdlJkSlFSVUlsRXBHSFNrTzJ5OQpkVHVqUEFYZEF6L0J1WW4vVzdUNTVWcGpNMVdDbjkzL212MjA3cTFDSnZONXpUOWs3WHl2RUpialAwYVhTTW1jClhETWpmZWhPa0l4eVplZHFNZWErdlVRVisxeHVuOUxLTDNhckF6UXBBZ01CQUFHalVEQk9NQjBHQTFVZERnUVcKQkJUQmhROUd0R2xVRkVla2xqaVJKc1lRZjRaT1BUQWZCZ05WSFNNRUdEQVdnQlRCaFE5R3RHbFVGRWVrbGppUgpKc1lRZjRaT1BUQU1CZ05WSFJNRUJUQURBUUgvTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElFQVFCQ05idDZOZDdVCjlHZ0dCbGtLREFEbk9TRGE0dVlmbnd4VHd6cS94c01wTTB1a2dUelpNdjVLYmFQY2hsWkMzZVpFLzU4VXNyU1QKdnF2WXBIOFUyVUhReDRVcExuY215ckVYdGxvampHOTN1ZWpWUVBPTnhHbEdlRHVRMGgzekRnVWtjNnl6MVc1KwpDZlpSTGplcm5PbDFSWFJRY2c0OTY2WGhHU3NjUmV1ZVYraDVqRlE4eE15T0dmckNTVFJZcUNyK2hrd3hvM2NTCmpLTEJNSFJKZ2JqYVpGbFczRTFDNnZhZzFtRG9SMWRobUpZVjgwbWFXM1pwbmdybHJQUnpNenJCSmFYVmIwN1gKR0Z4MU1ST0NtREMya2lkdmQvWXRrckQ1ZE9XZXJBQWc4VGY0TlBMeFBRWldjMHljMUlrR1ZUYVF0MVh3T0pDVwpJMXVTbWhpVWFtdlcyK3d1TEdEWUtDcS8yR3oySVVxZjRqOGgyWUNWYUlVRSsyR3psRGpsazlSb21tdXBrR1hvCjlRZ3ZqZi9kaDd5NEptNDNURE9Zb2xyeEpOT203SWNpdVJqZnl0ZlZWRnZvaEttRktMNmZTN296T1hCRnpUcHMKclNXOWxYN0FjZWsyM1dIZzRBc1lCY3NIbzAzTldlcmFvVFBleVZSLy9Qc2lETzlUUy8xOVJBdVpCZnNGemZZMAo1TVNXcFpYM0g3MXBMUURMdGVjVnZDeVdxemN6elNGcHl3dmhZbGJUWFgyZGl4QmRuTEZpWFJkWmhKd3lFQmJXCldsWTNIdDV1Ny85c1BEUW42ZStIWGwxYlEwNkVXN1ppTmJWbUNvdHdMOWFDN2dtdHVqeEFTQnNZWnNmRnd0WHAKd0FwT2ZNSGtrZmxuNFBpc2FXT0gzelFNWEdQZTBmTEp6bFRXTlV5ZGxSS0JPY2I0QkNlK0hRQWZiekM4eVNXcgp0NFdHbWlYdkRvYmkrWVhXT3FwcFhOQWpZQXZEd1l1ZC9OT3o5V1VHc1JwQ3ZDbTNKNXpxUHEreE5xc0VEVndLCmEyZVR6Y2ZmTGhEZmFmRjg0b1hYKy92OFplYWZicDBnMjlYdVVtQnM2YnZud0YvMVMwTU5OYi9reEVsR3QrdzQKWE4vNFVybzcwcHIxSVRQQmxIT2R0VGQ5QkVpeDZ1SEgxQ1Z4eHQxMUxlT2x1bk9JdllOcUlqcmNtT1pWaHJJSwphOWZpMWlqZHdPT09ENFhLdW9sVEo2dVZiR3ppS0ljVmNqTU1NYjAzZUx5ZjZUNS95bGtUeVV5UzZPaysrMDdLCjBHWjkyb2xxT012U04yQ3c3TkR3S1FaOW0zMmk1WG5yZVNBeEszcmg2aDVZTkdnNXlyTkJCYWxMZTloTUZVVjkKaDdKMUxUY0c2QXNUU3BzbnJjcno1cyt5MEd5c0V2YlI1Tm4rZWdDWXBZZEZxa3BDYVQwN2VMcnk5WUVaODRKRgp2amNGV2hmSnlTaG5wWXhRaVJzN2dwRWlVcDd6cDFZbW43MWpvR0FpejhJZDVNNEJsOWZ0YXZRQWY2eDM2RUEyCkZjdU9ROEc4ZSt3Q1FyR2tMT1JTZVlYRkhYVTVhVk8xVXJpWElIVzF6ZU55MGNRajBvR2czU2JYSVAwRVJVSC8KdkxHc1YwYWFoaHBONjFTSW9RcEdkNnFYODVhLzZTdjVUZ1BoMXRFcTRGQTlHM0cxeFVyVTBnWTJHWWlpWDg5RgptWWtUbUd0bEhoUFFhQU8ySHhadmJxYVlnMXZtWFZFSlRJajRBZmpoR0VoeER3bEdFMUJGRUc1TFNCakd1d2RFClhYZTRBc3U2ZDFxVwotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
private_key = Base64.decode "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlTSndJQkFBS0NCQUVBL3ZFT1BOcWZWZGRWSlhybzI4R0FJeHNFMXRibFl2MFUyUGNNcW9Hei9LU3BZdll2CmhHU0t3a2tXR0lvcWhhaFRCaVFhcHpmMU9IRjN6c3MyYmh4NzVoZHBYanpSYnFUNnFmVEQ3azZZaHBTUm5udFUKMk1tR1ROMFZERk5qRTNibUZ2YzhPeVNBeXZkL1ZQR3A5VjMweXhxdUJnaTFsdTlBa3J1R0FlU3FQMFh4dE04VQpRMUlsYWZXNG9LaGNOQXlSVlMyZTZEUzlHSmdKK3IxK3NXLzJaWUZnM1MyZ0hhK1B6MnY3VE4xYnNPSVMrZ2FzClNpTmgzV3NhalVjYzNWMXZWNFZLNXB3a2ttZHVubFpZUlVFdWdTRHpWSm44ZVlvcVlMK3pTdmFSRjVpUjhVNkcKSER0RWFZU0ZXR25GMzlJU2M5bjMyeUlDRmN5ekJHLzhyUDNVcVFCaDNSZGZzVzJnR2Q4RDN0cUs1elFnTGNpUwpNcGhMN1ZmWDZEa2xOcmhIeWZTRllISnhKODhvcjRKRDRkSjdBUzdBMVlxQ1doTjA4VUh6N0o0QUlIZExXOWMyCjQ3VlZNT05ITFVaVDR6bHQ0MnFIVGJYOU1DVjRMWEM2b0tlUVZJakhXN2VLOWRxa2lGdTR4MGlCc1owNVZlNG8KKzI3RW53MUtLRDRwd1ZZVm1pQUNoUVV2TUN0cER5UERiUFpsYU9WdU54SkpHcjM3TDdoMTN4VkIxMGRENnNieAoydTZqY3lhVExCdjlKbXNkODhXUjJBTnZ6OGRBNnlkd3ZhWUtIdkR6YVAvajd6SXlwQXlRRHU2K0VYTUVWZWtRCldtbGlscHlzMSt6U21uQy82OURvMFFSQUdDcGdON0NRMGo5enNxTmxXb0M4VGtJN2J2U1gwbk5RbWF2UjZqaFEKQ1dad2wzLzRhQXlHNWdwSy9CK0ZzanY1bFJ1N0d1QklJUDVhc2xhWDdmTHhXUnUxRU02WUhoTnFjdEs4VWtGUAphU3Nqc2JodDdHYXFCMVd2em1vQjRQTFpUUVlzOEVmR0U5VlRKcFAybGdzUmVwMHVPM2J2OS90eWJPZ1FUZS9UCnJaRmd1UHFScGE4OE40RnBwcWNSbUxRK1A0VkhINEN2dmhwQ01FejB6S2tsK2ZocmZmSnZ6blRtblFJYVgzaUwKR05PUEVsc1VSeFFGaFprK2ZEY05DUnByWXBJUXlkZUNZb2RVaEErMmp5YlgzRzJQS1F5T0JCZUNxbGpDM2hYZQp5U3dFczNJY0RQcG5GN0YxR2dGMXZkRGVzeEdZdER3dDJ6ckxBRWVzN1RIN1NCVTZJQ1UwU2ovdmFZdlRuVVgzCjhraFRVSWo4WG9Sb1RTbnJhQStobVcxeDBXRmhaeG0xN3VraGpZbVo4UTBieUMrVGhWdTV5bWhsVW51SVEzMGUKQjg4TlVrNFcyMmYrTHJVWHZBSVJYUkRIUHRXY2QySHhici8rZ0dJTGRibHpBYjF5VVpWcy94VFIzYjY2KzF2Uwo0RFlreDhIMGtacmFMaXFzQ2VCaWRvT1UvSlhDVUZEWVdNZTRvdUF0YzlFOUZmVEZTZWd1M0s4M2pVdldXTGhpCmp5NHYyMG1SSzNIcnNhc1k2UkR6ZzB1Q0lhNE1EdFJ3YVNXOFJmTzJsdzcwWFNVRVZDSlJLUmgwcER0c3ZYVTcKb3p3RjNRTS93Ym1KLzF1MCtlVmFZek5WZ3AvZC81cjl0TzZ0UWliemVjMC9aTzE4cnhDVzR6OUdsMGpKbkZ3egpJMzNvVHBDTWNtWG5hakhtdnIxRUZmdGNicC9TeWk5MnF3TTBLUUlEQVFBQkFvSUVBUUM3QW9TWkt4MjZVRXpMClE0L1FzKzZVMGRzSTVYWTYyTDhVTUpULzlramJTTVpnSzRyTHFSMElTNmlEczhaaGFRb045U29BQTlKRDV5Z2wKYjNlcjZnVVEwWmVmWXltVjZqdGR0SWlOSk9aSndtM1hQVTBPQVRZYzZBZnFsTGlXcko4M3RZQmZPZlduN1VsZwpQQzJhS2FQSjRQWkt3dFRCdFJzL0I0UFRtN011MnRYazlnbzlIK01HQ1JPMzlnZzh2Z05WNGpNd3pvN3ZuWWVrCmdLQ1E5RHBnVnptQXhWa3dyWG5tZzZWQnl4YlpkOXpIdjJGZXVQbXUvRVByNG9CUCtad1ZMVmUyTmsrMWZWM3QKbEJVSUtEbyt5cmIwRmtqWHR2eERJQndiSHlkcmthVnN4MWNsR215aW9tMVdYN0NnOEc1TXdWVkpUM2NNR3E0dQowUjhlbnN3Q2RKOVZHVEkrNnRXSVpNbG9EaFBhYWFnNUxXbmc1MHE2L2JjSlIvSCtZOHQxWDRML0xyUEdxZldFCldTQUdaT21LQW91OW1PN3B1R0FPSVgwVzB3Znd5TkZrdTBndVhQUHkrcVZabHI4dWJSQW94Qm9nYlNFZTBqMkgKeDZ0KzhhdXo5dW1XWTlyeFljTlRxMFN1R29mWWpDWmszR0QvbjA5b0JNMmpHNFp4cGY0T292QjJOMGxZSWwvYwpsVFZqbHBMcEVYTjV2bFlWNGNxQ1JPTmlFeXZMQ1NITzlNU3cvbUN6dFZZOEF3UDl6SkdhSWhGTHphbVZWdXBPCkZRNWtiNG41REhMaFVPUVlzRS9wZXJXcDNvTmFOVzYydmxJYW9EZUxsNzVLWGhSVzZlSSt6MjRZOU84M1NzNXQKeTMxUVhPODMyUmdkL1ZVa2F2MUI5UFh4a0ZsTmZ2K2RqMWs2Zi9YVUVPUTVyVGYrQUxvTnFDU0JoVi9KeTlBSAp0azBNKzgyZ1lFQ3hFOWdocVVub2ZieDVFN3BUdUR0bGtReGZMd0pSaXI1M2ZudkczaHZya2xsZkdMWkltTEJpCnYrNm0yVm9SeHEyaW9sRjU1NG5ONC9xMm5SUG5PelBadjU0YUxjUXU2dW1nMVhZOXNsQSs5NTV3OEhERVpSYzkKNjBrdE1EZ1BIcDVYb0pvMTZ2clo0bVVuOTRzanh0Q09QQkpPbU1RNUFodEdsY0ZzVEx1cWthV29hZEgxdDNLZQpsME9NcjdaZXVQMGxGN2t1bkcvMnNqNXpqL3ZFV3RIeWNDaEJsd3VZZitsVVhGMzZWU1czWkJBTnFyN1phZExYClZKTUp2ZlhuZWNRZG1IM2tuck9VdUp6OGxTbU5iZHlZeHZ6dHY2T0xWQUdrYThFRlEvdnVMWi8vd3RkTWVtbDAKZmprM0RFckRVV1c1clBqS2tTNlgwZWZEQ0FpcWZyUE5pbkR4dzFSOS81V2ppejFsTEdGL0JoNDRtWjBZbll5MApNalA5MTQ2V2Fsakc5L1ZIREJua3dnTEtHbzlIbzVHck1iK1RpK3ZkOFN4YXZINmo1RFlYcFd4NW9XSlRFV2J2ClhvV1ppUi9EYk01cmNQSTVEWFRFRTJBdXdQcjNWaWJDRVVieUx1dmZFMDlTN1M3aU4wdlF3UUJCTW9mTHpuTHgKTi8vQ2diZWFNOExxQ0FsRWIxNUZLNThtMERHOXZPZHZyM0pLUnVhVjU1YkQ5dk9FV2dlMTJpbG1Sb1dpQmR1UAo5a3VhOW9IYkQ2N25JNkJBTkNndXdtdVJ3M3A1eklMNkpoV2IvajIzWVYvS3VBUTMvbi9TZnNJYjAweVdoa21iCk1IT1hvcUVwQW9JQ0FRRC80aW1mRjdhLzROdnF5NW5vQ0J1UnBkRUFtbWxIVThhYmtoTHdZdkFJS3ZwbHpqZ0EKVjEzYjEwWEFXcEZNWENHcVN5L1Fvd2loNHNxZ2d2ZForZXo4SThkL3R3V1I5RHdHamtRb3BORVkwNkt0N3BkYgplVi8vV3cvRkdiTFd1Mm5QbzRRb0Z1S29tRG5uSEhRV1l5V3lvbkQvOUdRamovbnk2eHZ5WDkyNWE2aldlV2hLCnJmZnJIa0xyTmt4NFhLaTBBV2txN1NlaExJb0dvSE9GT1VoRjlWcXNhSWNWSm1ibldVMjg4cUFrWHBpcnFJZmcKTXc5MTVVcXhFMnYwODdoVFBIcklBOGVOdzRwMFoyZnprTEV5MnppNHZ2VUdCdjZQYTBtNTQxVTNjcklETXo3WQpGaDFEdzVpWEpQLzdlQUI3WVVqMGFXTUgxQllQRUErUEtZZExtdFdiL3UwVlcwZHZBalFxb1o4cHB1TTJ2cHFoCit4eTNkaDZrVXAzTE5yTmE5UkNVbERuUGpPc2VqelNIZkdTQi9Udkc5aXBBN3BXVG9iS0xKK3M5a2hqRXBSTzUKRzZ1S3JMMEp1aDVlVTU3djVkeHh6T0lSZXR3NGgzSFFwbXpvOThOb2poSzRqUDNING1VYXVuRzFnUkJ4MEdtUApOVFg1SkE4am91dGZVdy9JUmN6TndVbWNNby8xNjZ3OVplNWgzeHk4d0dBRDFQL3E3MDZPV3lxSWszWDdUK0VlClpJWHRycjJWeDNIdFpMR3VNNmRPWHlQVTVWWVg0TGJVSnd2cnFvdnZLbWhIWndMNklqS3RiSVAxYmZaVFptVTYKT3g3OW5jRXU3anRqQzZtTktxRkNYR2lxUmxwVkIvL0VrQ29xSHBJcVY1ZmFKdGtORjgyQk1JeHIrd0tDQWdFQQovdzdJZ0huQ0Y1Zzl2czZTSFhoMnVqS2dtYmx3OFAxVk10dEJLN2ZVNTFWREU2cjFSRExTTHFGWUtvTUZHNnlKCnBkMWhnc2I0QStYdGc4a1JxSWNHVjdRUEQ3Z2JjMmtjZmc4R2xEVFZqYldjOHBmV3gycXo5NFVHYUNBWHRjdWkKTm5Vc0ZCUkt6cTU0T0dOWG9hZGVZTFh1djFLM2QybTQxQ2EvYTdYTG5ScGNmNWUxUm4wbGdja2dpR2U4K1hRbQordFpCWXVkMk1jWGY4TndOd3hNcWpqaEJTWTc1TkZreGxRbng2SnJBd2FCY2s5SHNRL1ZMa3lsUHhYLzgrbkNoClVZUXR1bitvaU4vanVkQ01KUC9WTGFKWUJOMW03NVI3QUt4a1BRQXdJVWRtdUFoMXpDVVJaNXZTUkoxQmlnQ2IKWE16RkgzU3RzWlc4S2Q5RlpNZWlFR1V0RkxWMm53ZHM3eFoxbEdQMGpld2xCaWFac3JxbUhVbDErczR0T1pKbApxUjA2cTMwVTMxdzBVQ2Y4U2xZSUZjdmE2ZDFCNy9aMFYyeWE0Q0E4cW5MQ2V4R2NKbmorVUdVcS9sWWM4ZEdICmtxL1ZXc04vTU5MWEM5ZXNjWHc1UzFkb0FhMVNkSEhLQUorcnlweUsrc285K1hqcDlHK1JHOTRRZk5kLzZIL1cKc2pGc0g5WGhtdWE1ZDBLNjhrZVNiRFhCQzNUWmNsRHpHMmZkZHlmSGFNSFhic0hTZmcwR0lEZS84Ri93ZFpuaApkQmNGb0xQdEtPRXhXbzRod2pFN3BYdXYzRGY1T1hPVGNnNnFacFBxZHFRWWk1ZEwwbEhuRXpma2o2RFhPRzZGCk1TNzFTMlowUG5zOVFyeUF0Qm1GN3IyTW55VkY4OGZ2MXNMajVmNFJZeXNDZ2dIL2ZmRFNpM3NnZDFBMDdWdEkKWk91WXBoYjJ4MVU0ZStLLzNkSUhnRWt4MnROTWFzOFV3UlkvRy9UWVg5UXpyMkdwTUNmUllON2RZTkErNnNHSwovTDRGNWhPMkhTWDNsOTZkckp4WTc2Z3ZRZ2pvQ0xObHk1L3huNzB5QmRDZ05SQUpCQ2wyNGtSaFNwbWg1aDRiCkJPbkhwQ1JQZWFyUG5yRStWRkZqYitlL09ZUERsY3dyaUpZWGI2RjFUazlyVTlKSE5sRjdjYVZIM0F3UDR6TVYKcUh5SkZlV3N1eTYzVGJHWTlFVC8vZjlzMG5tOHFzQklJQkVCaXdWUHZkZlJTcjZwK2szS0lLZTdrQXF1R3B6SwpqUmFxSUYzRmpTaHZjSWdBd3BZTHMzSXdmeG4wZzU2MVQ2V1N3Y2VEVXVEakhPSHpXc2FISWNTOCtSMXB2Z0FwCnFFeklTbTNxdE56RDA3OFphWW1zSTA5cEJ4Y2N2ZFVTUnFkUmV2cW9HamlQY1hWNjBVbk0zMVFWSUJJN3BzN1YKQzlvdG5jMEZudWVKNUd1Sk15Qml3QnJscldnNnlJNTNKcVIzeWNrN1FZNVpaQlBFSms3OE1RYW1QZlE2YjVnNgpiSGQ5SXl6UEFLYnNqK2pVLzR4dU5ybU5QY2hJVDd4RU9EZjRXS2RtekNOanRZY3NQV1lkWnllN0V5WFB0VHBKCmkrNmZaWXhxbUh3V3hjd1FLWkdmR0hIR2ZYSVduNXF4TWtSSHByUmFtMTJPdFVqYUt1TkJkVkZlVVdxTzlUR2sKeXNadEY1RFpUdDJRZFpROTR0N3lFbWxXaVhXVngzYWVYQXE5TmhadS9xcENrSDBzOWs0RkVLUnEzMlBCRWhqZAp5ZUVxMzVBc1lLcThFcU1NTVdXRndCQWxEUUtDQWdBR25MaC85Q2dlK25oblVPMml5L093QWczOXpqdnFVM2I0CitZd24rUDBRL2puZDhhbW9HZlV1OWtuVjJFMnltUGQ4a0UrdDEwQ293VFkyRzJsVXlDTlc5TGtMUEVlaDUxQ3cKeCt6d3ZLbm9vWk92Q2xhc0ZzMFJscVpDM3NvZWtXZmtKNGQ4QWNhcXN3VTAyUVoxajJRMzk1OTM0RW9YVTJ0UwpQS3Jydk92Slo5eU1Cai9SMHY2ODdaemxUR011eUY4V1U2V2dUY1hYcG55V3Z1MndaL2ZMZGhQak4weW9tY05hClRNYXp0QWRaUGJJSXR3RjhCWWp2Q0x3anI1eThWVjBwUXRiNHBjU1Z2OUFraWc2SUN3WFl5QU9tSktNOWhNam4KakpDUXNFZVBKVTI1YWFhOEl4M2ZaTCsvdlovc1Z2V3dJekxkRE9aUDIwVGtoUUJFaTVSYy9uSjd2ZlNVVE5uNwpITWJ4a09IUEtCY1JvTUNOVEo5djFPNjFFTkZGVTlGRTRCZ2NTQUxaZzRkcnFJMjIwNklrQm9QbldqQVNhMzQ2Cm9mc2w0bEFRVHlkUmozUlAzd1VneW02aDUxT2F4VWJSZTdONVJlWXZPdGdPVzRvQjZ5bUZGWUFCd3grSEcwZ1UKV2c5WEVsWGNDSkF3dm55Nk5JWTdoYmRCdFVpQW00ZlNXTXVueTZDc3BseWFoZVZZMEpnd0svaVVOblJJcldhUQpDRkpLZTRLRTZibVBDb0ZOZVVMMlpOdVovTEs4S2NBWmhWdEUva1Vnc1MzWlhpUHI1K0RXK216bHRhSEZab1NsCkNWSkxsSHdZbFVwNW0vT0FRVlZQUHp5eXFJWEwxYm1vTzhKcU1QN0VlK2RycW4xZnJlVzErYjRDaGpIWkR3N2QKcjNHL0RhWWZ2d0tDQWdCWTlXRG9qVTJ2c3hTUzN0S3JrTkp4YWEyeEZkZCt5MTRZRkFYNEtpb0FzMXlLd2kvUgpEN2FqZFBMckJZbkV5MWQ0QzZndzFnbVVZMXEyNW5YSUViMjlFbmJVaEZjQnZWT3htVkVsODI5SmJzTE1raTBXCndsTU5uZ2FBR1ZQZGluOGNmZGpxTXh0RFMyWjlVNG9EUTBwaGdTSVNHdy92OEhRTjJya1pKOFNOdHZHQ3paVW0KejlEVUthZDBWSTFsdFFVZWo5L2RWUHlSTHVMTVdIUE1YTnkwQ2ltSE15bU80dUNrdG9TRnY1N2VqZm1UNzNoaQpnTmt2WWNjMkp3UXgvR1dVUzl1c1ZQVWcwNFBQRGxPYTZzVHFLeVJMZGpkVUZjZXVoSVRPWnlRYU1JczRPc3ZGClJGUmk5Uk1rZEZEOHhYT0NPd0daSFhBZ0huQW1RckFaNlVqbXk2OUR0eGNBWmt2bXdXRWh1Wk4zUUJTaUV6N3gKQlhlNDNjTVpzMml6RnNGWlRBV3dXaXZaRmhDc0U2MUNQVE51cGFNNUpnTXdwSThNRHZVOE5EVE9BVjdSN1Q0Ywo3aHdiVXZFRGNpYmxoaFM1NlVLOElPNE1BZkhIRWo0elZDZDA3Q3J1cGtjbDZxbmczcVRoVlNpc0kvYmJhRFZrCitYK2daaTB6KzY2a0hkNWwrQUNrTjVPZUdTaDdxNXVPT21wVW1GWXAxRnhpeGFyNy80enVQS25Cb3crcnozbEIKcGlSWnJHNnZZWTdjcFQ5Rkpac3NpSm5xMElJMDNPUU1KY2RZaWRDZjZnQ1hKRWVqL1hhTFpmOW9OMEY2N1hETwpNU240RDZScU5USUNKNDE4RDI0Ly9oYWx1d1gyYndmU3dtdGRzL0RHMyt3RGhyekpna1JRQXZlTTlnPT0KLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0K"

mitm_context = Mitm::Context.new rootCertificate: String.new(certificate), rootPrivateKey: String.new(private_key)
context_server = mitm_context.create_context_server hostname: "www.google.com"

server = HTTP::Server.new { |context| STDOUT.puts [context] }
address = server.bind_tls host: "0.0.0.0", port: 1234_i32, context: context_server

puts "Listening on http://#{address}"
server.listen
